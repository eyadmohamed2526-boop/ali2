import os, secrets, re, base64, json, tempfile, mimetypes, hashlib
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from authlib.integrations.flask_client import OAuth
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


def env_bool(name, default=False):
    return os.getenv(name, str(int(default))).lower() in {"1", "true", "yes", "on"}


def create_app():
    app = Flask(__name__)
    free_launch_mode = env_bool("FREE_LAUNCH_MODE", True)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=env_bool("SESSION_COOKIE_SECURE", True),
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if database_url.startswith("postgres://"):
        database_url = "postgresql://" + database_url[11:]

    pool = ConnectionPool(
        conninfo=database_url,
        min_size=int(os.getenv("DB_POOL_MIN", "1")),
        max_size=int(os.getenv("DB_POOL_MAX", "5")),
        kwargs={"row_factory": dict_row, "connect_timeout": 10},
        open=False,
    )
    pool.open(wait=True)
    app.extensions["db_pool"] = pool

    oauth = OAuth(app)
    google_enabled = bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
    if google_enabled:
        oauth.register(
            name="google",
            client_id=os.getenv("GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    def get_conn():
        return pool.connection()

    admin_emails = {x.strip().lower() for x in os.getenv("ADMIN_EMAILS", "").split(",") if x.strip()}
    # Free-launch mode deliberately disables metered AI features. They can be enabled later.
    ai_verification_enabled = (not free_launch_mode) and env_bool("AI_VERIFICATION_ENABLED", False)
    ai_verification_endpoint = os.getenv("AI_VERIFICATION_ENDPOINT", "https://api.openai.com/v1/responses")
    ai_verification_model = os.getenv("AI_VERIFICATION_MODEL", "gpt-4.1-mini")
    ai_assistant_enabled = (not free_launch_mode) and env_bool("AI_ASSISTANT_ENABLED", False)
    ai_assistant_endpoint = os.getenv("AI_ASSISTANT_ENDPOINT", "https://api.openai.com/v1/responses")
    ai_assistant_model = os.getenv("AI_ASSISTANT_MODEL", "gpt-4.1-mini")
    verification_dir = os.getenv("VERIFICATION_TMP_DIR", tempfile.gettempdir())
    allowed_doc_types = {"image/jpeg", "image/png", "image/webp"}

    def is_admin(user):
        return bool(user and user.get("email") and user["email"].lower() in admin_emails)

    def init_db():
        with get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
            version = conn.execute("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").fetchone()["version"]

            if version < 1:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        username VARCHAR(40) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        id BIGSERIAL PRIMARY KEY,
                        title VARCHAR(120) NOT NULL,
                        description VARCHAR(5000) NOT NULL,
                        price INTEGER NOT NULL CHECK (price >= 0),
                        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS interests (
                        id BIGSERIAL PRIMARY KEY,
                        job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        UNIQUE(job_id, user_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_user_id ON jobs(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_interests_job_id ON interests(job_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_title ON jobs(title)")
                conn.execute("INSERT INTO schema_migrations(version) VALUES (1)")

            if version < 2:
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(320)")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub VARCHAR(255)")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id BIGSERIAL PRIMARY KEY,
                        sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        body VARCHAR(2000) NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        read_at TIMESTAMPTZ
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id, read_at)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS ratings (
                        id BIGSERIAL PRIMARY KEY,
                        reviewer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        reviewee_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        score INTEGER NOT NULL CHECK (score BETWEEN 1 AND 5),
                        comment VARCHAR(1000),
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        UNIQUE(reviewer_id, reviewee_id, job_id),
                        CHECK (reviewer_id <> reviewee_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ratings_reviewee ON ratings(reviewee_id)")
                conn.execute("INSERT INTO schema_migrations(version) VALUES (2)")

            if version < 3:
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(1000)")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(30)")
                conn.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS category VARCHAR(60)")
                conn.execute("CREATE TABLE IF NOT EXISTS favorites (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(user_id, job_id))")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id, created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_favorites_job ON favorites(job_id)")
                conn.execute("CREATE TABLE IF NOT EXISTS notifications (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind VARCHAR(40) NOT NULL, title VARCHAR(160) NOT NULL, body VARCHAR(500) NOT NULL, url VARCHAR(500), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), read_at TIMESTAMPTZ)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC)")
                conn.execute("CREATE TABLE IF NOT EXISTS reports (id BIGSERIAL PRIMARY KEY, reporter_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, job_id BIGINT REFERENCES jobs(id) ON DELETE CASCADE, reported_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, reason VARCHAR(500) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC)")
                conn.execute("INSERT INTO schema_migrations(version) VALUES (3)")

            if version < 4:
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN NOT NULL DEFAULT FALSE")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_status VARCHAR(20) NOT NULL DEFAULT 'unverified'")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS trust_score INTEGER NOT NULL DEFAULT 0")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_verification ON users(verification_status)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS verification_requests (
                        id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        status VARCHAR(20) NOT NULL DEFAULT 'pending', ai_result JSONB,
                        document_sha256 VARCHAR(64), selfie_sha256 VARCHAR(64),
                        consent_at TIMESTAMPTZ NOT NULL DEFAULT now(), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        reviewed_at TIMESTAMPTZ, reviewer_id BIGINT REFERENCES users(id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_verification_status ON verification_requests(status, created_at DESC)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS moderation_actions (
                        id BIGSERIAL PRIMARY KEY, admin_id BIGINT NOT NULL REFERENCES users(id), target_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                        target_job_id BIGINT REFERENCES jobs(id) ON DELETE CASCADE, action VARCHAR(40) NOT NULL, note VARCHAR(1000), created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS conversations (
                        id BIGSERIAL PRIMARY KEY, job_id BIGINT REFERENCES jobs(id) ON DELETE SET NULL, buyer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, seller_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        status VARCHAR(20) NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(job_id, buyer_id, seller_id)
                    )
                """)
                conn.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS conversation_id BIGINT REFERENCES conversations(id) ON DELETE CASCADE")
                conn.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'open'")
                conn.execute("ALTER TABLE reports ADD COLUMN IF NOT EXISTS admin_note VARCHAR(1000)")
                conn.execute("INSERT INTO schema_migrations(version) VALUES (4)")

            if version < 5:
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT")
                conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ")
                conn.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS min_price INTEGER")
                conn.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS max_price INTEGER")
                conn.execute("CREATE TABLE IF NOT EXISTS offers (id BIGSERIAL PRIMARY KEY, job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, buyer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, seller_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, amount INTEGER NOT NULL CHECK(amount>=0), note VARCHAR(1500), status VARCHAR(20) NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(job_id,buyer_id,seller_id,status))")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_offers_job_status ON offers(job_id,status,created_at DESC)")
                conn.execute("CREATE TABLE IF NOT EXISTS orders (id BIGSERIAL PRIMARY KEY, job_id BIGINT NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT, offer_id BIGINT UNIQUE REFERENCES offers(id) ON DELETE SET NULL, buyer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT, seller_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT, amount INTEGER NOT NULL CHECK(amount>=0), status VARCHAR(30) NOT NULL DEFAULT 'pending_payment', payment_status VARCHAR(20) NOT NULL DEFAULT 'unpaid', payment_ref VARCHAR(255), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id,created_at DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id,created_at DESC)")
                conn.execute("CREATE TABLE IF NOT EXISTS disputes (id BIGSERIAL PRIMARY KEY, order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, opened_by BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, reason VARCHAR(2000) NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'open', resolution VARCHAR(2000), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), resolved_at TIMESTAMPTZ)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_disputes_status ON disputes(status,created_at DESC)")
                conn.execute("CREATE TABLE IF NOT EXISTS password_reset_tokens (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash VARCHAR(64) UNIQUE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_expiry ON password_reset_tokens(expires_at)")
                conn.execute("CREATE TABLE IF NOT EXISTS audit_logs (id BIGSERIAL PRIMARY KEY, actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL, action VARCHAR(80) NOT NULL, target_type VARCHAR(40), target_id BIGINT, metadata JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT now())")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC)")
                conn.execute("INSERT INTO schema_migrations(version) VALUES (5)")

            conn.commit()

    init_db()

    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("user_id")
        if uid:
            with get_conn() as conn:
                g.user = conn.execute(
                    "SELECT id, username, email, created_at, is_suspended, verification_status, verified_at, last_seen_at FROM users WHERE id=%s", (uid,)
                ).fetchone()
            if not g.user:
                session.clear()
            elif g.user.get("is_suspended"):
                session.clear()
                g.user = None
            else:
                with get_conn() as conn:
                    conn.execute("UPDATE users SET last_seen_at=now() WHERE id=%s", (uid,))
                    conn.commit()

    @app.context_processor
    def inject_globals():
        unread = 0
        if g.user:
            with get_conn() as conn:
                unread = conn.execute("SELECT COUNT(*)::int AS n FROM messages WHERE receiver_id=%s AND read_at IS NULL", (g.user["id"],)).fetchone()["n"]
        return {"current_user": g.user, "csrf_token": csrf_token, "google_enabled": google_enabled, "unread_messages": unread, "is_admin": is_admin(g.user), "ai_verification_enabled": ai_verification_enabled, "ai_assistant_enabled": ai_assistant_enabled, "free_launch_mode": free_launch_mode}

    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    @app.before_request
    def csrf_protect():
        if request.method == "POST" and request.endpoint not in {"google_callback"}:
            supplied = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(supplied, expected):
                abort(400, description="طلب غير صالح. أعد تحميل الصفحة وحاول مرة أخرى.")

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not g.user:
                flash("سجل دخولك أولًا.", "warning")
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapper

    def user_rating(conn, user_id):
        return conn.execute("""
            SELECT COALESCE(ROUND(AVG(score)::numeric, 1), 0)::float AS rating,
                   COUNT(*)::int AS rating_count
            FROM ratings WHERE reviewee_id=%s
        """, (user_id,)).fetchone()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/health")
    def health():
        try:
            with get_conn() as conn:
                conn.execute("SELECT 1")
            return {"status": "ok"}, 200
        except Exception:
            return {"status": "error"}, 503

    @app.route("/")
    def home():
        q = request.args.get("q", "").strip()[:120]
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        per_page = 12
        offset = (page - 1) * per_page
        with get_conn() as conn:
            where = ""
            args = ()
            if q:
                where = "AND (j.title ILIKE %s OR j.description ILIKE %s)"
                args = (f"%{q}%", f"%{q}%")
            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM jobs j WHERE j.status='open' {where}", args
            ).fetchone()["n"]
            jobs = conn.execute(f"""
                SELECT j.id, j.title, j.description, j.price, j.category, j.created_at,
                       u.username,
                       COALESCE(ROUND(AVG(r.score)::numeric,1),0)::float AS seller_rating,
                       COUNT(DISTINCT r.id)::int AS rating_count,
                       COUNT(DISTINCT i.id)::int AS interest_count
                FROM jobs j
                JOIN users u ON u.id=j.user_id
                LEFT JOIN interests i ON i.job_id=j.id
                LEFT JOIN ratings r ON r.reviewee_id=u.id
                WHERE j.status='open' {where}
                GROUP BY j.id, u.username
                ORDER BY j.created_at DESC
                LIMIT %s OFFSET %s
            """, args + (per_page, offset)).fetchall()
            user_count = conn.execute("SELECT COUNT(*)::int AS n FROM users").fetchone()["n"]
            favorite_ids = set()
            if g.user:
                favorite_ids = {r["job_id"] for r in conn.execute("SELECT job_id FROM favorites WHERE user_id=%s", (g.user["id"],)).fetchall()}
        pages = max(1, (total + per_page - 1) // per_page)
        return render_template("index.html", jobs=jobs, q=q, page=page, pages=pages, total=total, user_count=user_count, favorite_ids=favorite_ids)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not (3 <= len(username) <= 40) or not username.replace("_", "a").isalnum():
                flash("اسم المستخدم يجب أن يكون 3–40 حرفًا ويحتوي على حروف/أرقام/_.", "error")
                return render_template("register.html")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 320:
                flash("اكتب بريدًا إلكترونيًا صحيحًا، مثل example@gmail.com.", "error")
                return render_template("register.html")
            if len(password) < 8:
                flash("كلمة السر يجب أن تكون 8 أحرف على الأقل.", "error")
                return render_template("register.html")
            try:
                with get_conn() as conn:
                    if conn.execute("SELECT 1 FROM users WHERE username=%s", (username,)).fetchone():
                        flash("اسم المستخدم مستخدم بالفعل.", "error")
                        return render_template("register.html")
                    if conn.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
                        flash("البريد الإلكتروني مستخدم بالفعل. جرّب تسجيل الدخول.", "error")
                        return render_template("register.html")
                    user = conn.execute(
                        "INSERT INTO users(username,password_hash,email) VALUES (%s,%s,%s) RETURNING id, username",
                        (username, generate_password_hash(password), email),
                    ).fetchone()
                    conn.commit()
            except UniqueViolation:
                flash("اسم المستخدم أو البريد الإلكتروني مستخدم بالفعل.", "error")
                return render_template("register.html")
            session.clear()
            session.permanent = True
            session["user_id"], session["username"] = user["id"], user["username"]
            flash("أهلًا بيك! حسابك اتعمل بنجاح.", "success")
            return redirect(url_for("home"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("home"))
        if request.method == "POST":
            identifier = request.form.get("identifier", "").strip().lower()
            password = request.form.get("password", "")
            with get_conn() as conn:
                user = conn.execute(
                    "SELECT id, username, password_hash FROM users WHERE username=%s OR email=%s LIMIT 1",
                    (identifier, identifier),
                ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["user_id"], session["username"] = user["id"], user["username"]
                nxt = request.args.get("next", "")
                if nxt.startswith("/") and not urlparse(nxt).netloc:
                    return redirect(nxt)
                return redirect(url_for("home"))
            flash("بيانات الدخول غير صحيحة.", "error")
        return render_template("login.html")

    @app.get("/auth/google")
    def google_login():
        if not google_enabled:
            flash("تسجيل Google غير مفعّل على السيرفر. أضف GOOGLE_CLIENT_ID و GOOGLE_CLIENT_SECRET.", "warning")
            return redirect(url_for("login"))
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or url_for("google_callback", _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.get("/auth/google/callback")
    def google_callback():
        if not google_enabled:
            return redirect(url_for("login"))
        try:
            token = oauth.google.authorize_access_token()
            userinfo = token.get("userinfo")
            if not userinfo:
                userinfo = oauth.google.userinfo()
            google_sub = userinfo["sub"]
            email = (userinfo.get("email") or "").strip().lower() or None
            display_name = (userinfo.get("name") or email or "user").strip().lower()
            base = re.sub(r"[^a-z0-9_]+", "_", display_name)[:30].strip("_") or "user"
            with get_conn() as conn:
                user = conn.execute(
                    "SELECT id, username FROM users WHERE google_sub=%s OR (%s IS NOT NULL AND email=%s)",
                    (google_sub, email, email),
                ).fetchone()
                if user:
                    conn.execute(
                        "UPDATE users SET google_sub=%s, email=COALESCE(email,%s) WHERE id=%s",
                        (google_sub, email, user["id"]),
                    )
                else:
                    username = base
                    i = 1
                    while conn.execute("SELECT 1 FROM users WHERE username=%s", (username,)).fetchone():
                        i += 1
                        username = f"{base[:35]}_{i}"
                    user = conn.execute(
                        "INSERT INTO users(username,password_hash,email,google_sub) VALUES (%s,%s,%s,%s) RETURNING id, username",
                        (username, generate_password_hash(secrets.token_urlsafe(32)), email, google_sub),
                    ).fetchone()
                conn.commit()
            session.clear()
            session.permanent = True
            session["user_id"], session["username"] = user["id"], user["username"]
            flash("تم تسجيل الدخول بحساب Google بنجاح.", "success")
            return redirect(url_for("home"))
        except Exception:
            flash("تعذر تسجيل الدخول بحساب Google. جرّب مرة أخرى.", "error")
            return redirect(url_for("login"))

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.route("/add", methods=["GET", "POST"])
    @login_required
    def add_job():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip()[:60] or "عام"
            try:
                price = int(request.form.get("price", "-1"))
            except ValueError:
                price = -1
            if not (3 <= len(title) <= 120) or not (10 <= len(description) <= 5000) or not (0 <= price <= 10_000_000):
                flash("راجع العنوان والوصف والسعر. الوصف من 10 إلى 5000 حرف والسعر حتى 10 مليون جنيه.", "error")
                return render_template("add.html")
            with get_conn() as conn:
                conn.execute(
                    "INSERT INTO jobs(title,description,price,category,user_id) VALUES (%s,%s,%s,%s,%s)",
                    (title, description, price, category, g.user["id"]),
                )
                conn.commit()
            flash("تم نشر الشغلة بنجاح 🚀", "success")
            return redirect(url_for("home"))
        return render_template("add.html")

    @app.route("/job/<int:job_id>")
    def job(job_id):
        with get_conn() as conn:
            item = conn.execute("""
                SELECT j.*, u.username, u.verification_status,
                       COALESCE(ROUND(AVG(r.score)::numeric,1),0)::float AS seller_rating,
                       COUNT(DISTINCT r.id)::int AS rating_count,
                       COUNT(DISTINCT i.id)::int AS interest_count
                FROM jobs j
                JOIN users u ON u.id=j.user_id
                LEFT JOIN interests i ON i.job_id=j.id
                LEFT JOIN ratings r ON r.reviewee_id=u.id
                WHERE j.id=%s
                GROUP BY j.id, u.username
            """, (job_id,)).fetchone()
            if not item:
                abort(404)
            my_interest = False
            is_favorite = False
            can_rate = False
            if g.user:
                my_interest = bool(conn.execute(
                    "SELECT 1 FROM interests WHERE job_id=%s AND user_id=%s",
                    (job_id, g.user["id"])
                ).fetchone())
                is_favorite = bool(conn.execute("SELECT 1 FROM favorites WHERE job_id=%s AND user_id=%s", (job_id, g.user["id"])).fetchone())
                can_rate = my_interest and g.user["id"] != item["user_id"]
            interested_users = []
            if g.user and g.user["id"] == item["user_id"]:
                interested_users = conn.execute("""
                    SELECT u.id, u.username,
                           COALESCE(ROUND(AVG(r.score)::numeric,1),0)::float AS rating,
                           COUNT(DISTINCT r.id)::int AS rating_count
                    FROM interests i
                    JOIN users u ON u.id=i.user_id
                    LEFT JOIN ratings r ON r.reviewee_id=u.id
                    WHERE i.job_id=%s
                    GROUP BY u.id, u.username
                    ORDER BY i.created_at DESC
                """, (job_id,)).fetchall()
            recent_ratings = conn.execute("""
                SELECT r.score, r.comment, r.created_at, u.username
                FROM ratings r JOIN users u ON u.id=r.reviewer_id
                WHERE r.reviewee_id=%s ORDER BY r.created_at DESC LIMIT 8
            """, (item["user_id"],)).fetchall()
        return render_template(
            "job.html", job=item, my_interest=my_interest, is_favorite=is_favorite, can_rate=can_rate,
            interested_users=interested_users, recent_ratings=recent_ratings
        )

    @app.post("/interest/<int:job_id>")
    @login_required
    def interest(job_id):
        with get_conn() as conn:
            exists = conn.execute("SELECT id, user_id, status FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not exists:
                abort(404)
            if exists["user_id"] == g.user["id"]:
                flash("دي شغلتك أنت.", "warning")
                return redirect(url_for("job", job_id=job_id))
            if exists["status"] != "open":
                flash("الشغلة دي اتقفلت.", "warning")
                return redirect(url_for("job", job_id=job_id))
            try:
                conn.execute("INSERT INTO interests(job_id,user_id) VALUES (%s,%s)", (job_id, g.user["id"]))
                conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'interest','اهتمام جديد','حد سجّل اهتمامه بالشغلة بتاعتك.',%s)", (exists["user_id"], url_for("job", job_id=job_id)))
                conn.commit()
                flash("تم تسجيل اهتمامك بالشغلة ❤️", "success")
            except UniqueViolation:
                conn.rollback()
                flash("أنت سجلت اهتمامك بالشغلة دي بالفعل.", "warning")
        return redirect(url_for("job", job_id=job_id))

    @app.route("/rate/<int:user_id>", methods=["POST"])
    @login_required
    def rate_user(user_id):
        try:
            score = int(request.form.get("score", "0"))
        except ValueError:
            score = 0
        comment = request.form.get("comment", "").strip()[:1000]
        job_id = request.form.get("job_id", type=int)
        if user_id == g.user["id"] or score not in range(1, 6) or not job_id:
            flash("التقييم غير صالح.", "error")
            return redirect(request.referrer or url_for("home"))
        with get_conn() as conn:
            job_row = conn.execute("SELECT id, user_id FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not job_row:
                abort(404)
            allowed = (
                (job_row["user_id"] == user_id and conn.execute(
                    "SELECT 1 FROM interests WHERE job_id=%s AND user_id=%s",
                    (job_id, g.user["id"])
                ).fetchone())
                or
                (job_row["user_id"] == g.user["id"] and conn.execute(
                    "SELECT 1 FROM interests WHERE job_id=%s AND user_id=%s",
                    (job_id, user_id)
                ).fetchone())
            )
            if not allowed:
                flash("لا يمكنك تقييم هذا المستخدم على هذه الشغلة.", "warning")
                return redirect(url_for("job", job_id=job_id))
            try:
                conn.execute(
                    "INSERT INTO ratings(reviewer_id,reviewee_id,job_id,score,comment) VALUES (%s,%s,%s,%s,%s)",
                    (g.user["id"], user_id, job_id, score, comment or None),
                )
                conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'rating','تقييم جديد','وصلك تقييم جديد من عميل.',%s)", (user_id, url_for("job", job_id=job_id)))
                conn.commit()
                flash("تم حفظ تقييمك بنجاح ⭐", "success")
            except UniqueViolation:
                conn.rollback()
                flash("أنت قيّمت هذا المستخدم على هذه الشغلة من قبل.", "warning")
        return redirect(url_for("job", job_id=job_id))

    @app.route("/chat/<int:user_id>")
    @login_required
    def chat(user_id):
        if user_id == g.user["id"]:
            return redirect(url_for("home"))
        with get_conn() as conn:
            other = conn.execute("SELECT id, username FROM users WHERE id=%s", (user_id,)).fetchone()
            if not other:
                abort(404)
            conn.execute(
                "UPDATE messages SET read_at=now() WHERE sender_id=%s AND receiver_id=%s AND read_at IS NULL",
                (user_id, g.user["id"]),
            )
            messages = conn.execute("""
                SELECT id, sender_id, receiver_id, body, created_at
                FROM messages
                WHERE (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s)
                ORDER BY created_at ASC LIMIT 200
            """, (g.user["id"], user_id, user_id, g.user["id"])).fetchall()
            conn.commit()
        return render_template("chat.html", other=other, messages=messages)

    @app.post("/chat/<int:user_id>/send")
    @login_required
    def send_message(user_id):
        body = request.form.get("body", "").strip()[:2000]
        if not body:
            return redirect(url_for("chat", user_id=user_id))
        with get_conn() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE id=%s", (user_id,)).fetchone():
                abort(404)
            conn.execute(
                "INSERT INTO messages(sender_id,receiver_id,body) VALUES (%s,%s,%s)",
                (g.user["id"], user_id, body),
            )
            conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'message','رسالة جديدة','وصلك رسالة جديدة.',%s)", (user_id, url_for("chat", user_id=g.user["id"])))
            conn.commit()
        return redirect(url_for("chat", user_id=user_id))

    @app.get("/chat/<int:user_id>/messages")
    @login_required
    def chat_messages(user_id):
        with get_conn() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE id=%s", (user_id,)).fetchone():
                abort(404)
            conn.execute(
                "UPDATE messages SET read_at=now() WHERE sender_id=%s AND receiver_id=%s AND read_at IS NULL",
                (user_id, g.user["id"]),
            )
            rows = conn.execute("""
                SELECT id, sender_id, receiver_id, body,
                       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
                FROM messages
                WHERE (sender_id=%s AND receiver_id=%s) OR (sender_id=%s AND receiver_id=%s)
                ORDER BY created_at ASC LIMIT 200
            """, (g.user["id"], user_id, user_id, g.user["id"])).fetchall()
            conn.commit()
        return jsonify(messages=[dict(r) for r in rows])

    @app.get("/chat")
    @login_required
    def chat_list():
        with get_conn() as conn:
            contacts = conn.execute("""
                WITH pairs AS (
                    SELECT CASE WHEN sender_id=%s THEN receiver_id ELSE sender_id END AS other_id,
                           id, body, created_at, receiver_id, read_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY CASE WHEN sender_id=%s THEN receiver_id ELSE sender_id END
                               ORDER BY created_at DESC
                           ) AS rn
                    FROM messages
                    WHERE sender_id=%s OR receiver_id=%s
                )
                SELECT u.id, u.username, p.body AS last_message, p.created_at,
                       (SELECT COUNT(*)::int FROM messages um
                        WHERE um.sender_id=u.id AND um.receiver_id=%s AND um.read_at IS NULL) AS unread
                FROM pairs p JOIN users u ON u.id=p.other_id
                WHERE p.rn=1
                ORDER BY p.created_at DESC
            """, (g.user["id"], g.user["id"], g.user["id"], g.user["id"], g.user["id"])).fetchall()
        return render_template("chat_list.html", contacts=contacts)

    @app.post("/favorite/<int:job_id>")
    @login_required
    def toggle_favorite(job_id):
        with get_conn() as conn:
            job_row = conn.execute("SELECT id FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not job_row:
                abort(404)
            exists = conn.execute("SELECT id FROM favorites WHERE user_id=%s AND job_id=%s", (g.user["id"], job_id)).fetchone()
            if exists:
                conn.execute("DELETE FROM favorites WHERE id=%s", (exists["id"],))
                saved = False
            else:
                conn.execute("INSERT INTO favorites(user_id,job_id) VALUES (%s,%s)", (g.user["id"], job_id))
                saved = True
            conn.commit()
        flash("اتضافت للمفضلة ⭐" if saved else "اتشالت من المفضلة.", "success")
        return redirect(request.referrer or url_for("job", job_id=job_id))

    @app.get("/favorites")
    @login_required
    def favorites():
        with get_conn() as conn:
            jobs = conn.execute("""
                SELECT j.*, u.username, COALESCE(ROUND(AVG(r.score)::numeric,1),0)::float AS seller_rating, COUNT(DISTINCT r.id)::int AS rating_count
                FROM favorites f JOIN jobs j ON j.id=f.job_id JOIN users u ON u.id=j.user_id
                LEFT JOIN ratings r ON r.reviewee_id=u.id WHERE f.user_id=%s
                GROUP BY j.id,u.username,f.created_at ORDER BY f.created_at DESC
            """, (g.user["id"],)).fetchall()
        return render_template("favorites.html", jobs=jobs)

    @app.get("/notifications")
    @login_required
    def notifications():
        with get_conn() as conn:
            rows = conn.execute("SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC LIMIT 100", (g.user["id"],)).fetchall()
            conn.execute("UPDATE notifications SET read_at=now() WHERE user_id=%s AND read_at IS NULL", (g.user["id"],))
            conn.commit()
        return render_template("notifications.html", notifications=rows)

    @app.route("/profile/<int:user_id>", methods=["GET", "POST"])
    def profile(user_id):
        with get_conn() as conn:
            user = conn.execute("SELECT id,username,email,bio,phone,created_at,verification_status,verified_at FROM users WHERE id=%s", (user_id,)).fetchone()
            if not user:
                abort(404)
            if request.method == "POST":
                if not g.user or g.user["id"] != user_id:
                    abort(403)
                bio = request.form.get("bio", "").strip()[:1000]
                phone = request.form.get("phone", "").strip()[:30]
                conn.execute("UPDATE users SET bio=%s, phone=%s WHERE id=%s", (bio or None, phone or None, user_id))
                conn.commit()
                flash("تم تحديث الملف الشخصي.", "success")
                return redirect(url_for("profile", user_id=user_id))
            stats = conn.execute("SELECT (SELECT COUNT(*) FROM jobs WHERE user_id=%s)::int AS jobs, (SELECT COUNT(*) FROM interests WHERE user_id=%s)::int AS interests", (user_id,user_id)).fetchone()
            rating = user_rating(conn, user_id)
            jobs = conn.execute("SELECT id,title,price,status,created_at FROM jobs WHERE user_id=%s ORDER BY created_at DESC LIMIT 20", (user_id,)).fetchall()
        return render_template("profile.html", user=user, stats=stats, rating=rating, jobs=jobs)

    @app.post("/job/<int:job_id>/close")
    @login_required
    def close_job(job_id):
        with get_conn() as conn:
            row = conn.execute("SELECT user_id FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not row: abort(404)
            if row["user_id"] != g.user["id"]: abort(403)
            conn.execute("UPDATE jobs SET status='closed', updated_at=now() WHERE id=%s", (job_id,))
            conn.commit()
        flash("تم إغلاق الشغلة.", "success")
        return redirect(url_for("job", job_id=job_id))

    @app.post("/report/job/<int:job_id>")
    @login_required
    def report_job(job_id):
        reason = request.form.get("reason", "").strip()[:500]
        if not reason:
            flash("اكتب سبب البلاغ.", "error")
            return redirect(url_for("job", job_id=job_id))
        with get_conn() as conn:
            row = conn.execute("SELECT user_id FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not row: abort(404)
            conn.execute("INSERT INTO reports(reporter_id,job_id,reported_user_id,reason) VALUES (%s,%s,%s,%s)", (g.user["id"],job_id,row["user_id"],reason))
            conn.commit()
        flash("تم إرسال البلاغ للمراجعة.", "success")
        return redirect(url_for("job", job_id=job_id))


    def _hash_file(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _ai_identity_precheck(document_path, selfie_path):
        """AI pre-check only. It is intentionally not a legal identity/biometric decision."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not ai_verification_enabled or not api_key:
            return {"status": "pending_manual", "reason": "AI verification is not configured."}
        import requests
        def data_url(path):
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("ascii")
            return f"data:{mime};base64,{encoded}"
        prompt = ("Review these two identity-verification images as a safety pre-check. "
                  "Determine document legibility, whether it appears to be an identity document, whether a face is visible in the selfie, "
                  "and whether the images appear internally consistent. Do NOT claim legal authenticity or definitive biometric identity. "
                  "Return strict JSON with keys: document_legible, document_type, selfie_face_visible, consistency, concerns, recommendation. "
                  "recommendation must be one of manual_review, likely_ok, reject_for_quality. Never infer protected traits.")
        payload = {"model": ai_verification_model, "input": [{"role": "user", "content": [
            {"type": "input_text", "text": prompt},
            {"type": "input_image", "image_url": data_url(document_path)},
            {"type": "input_image", "image_url": data_url(selfie_path)}
        ]}]}
        r = requests.post(ai_verification_endpoint, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        text = data.get("output_text", "")
        if not text:
            for item in data.get("output", []):
                for c in item.get("content", []):
                    if c.get("type") in {"output_text", "text"}:
                        text += c.get("text", "")
        try:
            return json.loads(text)
        except Exception:
            return {"status": "manual_review", "raw": text[:4000]}

    @app.route("/verify", methods=["GET", "POST"])
    @login_required
    def verify_identity():
        if request.method == "GET":
            with get_conn() as conn:
                latest = conn.execute("SELECT id,status,ai_result,created_at,reviewed_at FROM verification_requests WHERE user_id=%s ORDER BY created_at DESC LIMIT 1", (g.user["id"],)).fetchone()
            return render_template("verify.html", latest=latest)
        if request.form.get("consent") != "yes":
            flash("لازم توافق على معالجة صور الهوية لغرض التحقق قبل الإرسال.", "error")
            return redirect(url_for("verify_identity"))
        document = request.files.get("document")
        selfie = request.files.get("selfie")
        if not document or not selfie or not document.filename or not selfie.filename:
            flash("ارفع صورة/ملف البطاقة وصورتك الشخصية.", "error")
            return redirect(url_for("verify_identity"))
        if document.mimetype not in allowed_doc_types or selfie.mimetype not in {"image/jpeg", "image/png", "image/webp"}:
            flash("الملفات المسموح بها: JPG/PNG/WEBP.", "error")
            return redirect(url_for("verify_identity"))
        if document.content_length and document.content_length > 6 * 1024 * 1024 or selfie.content_length and selfie.content_length > 6 * 1024 * 1024:
            flash("حجم كل ملف يجب ألا يتجاوز 6MB.", "error")
            return redirect(url_for("verify_identity"))
        os.makedirs(verification_dir, exist_ok=True)
        paths=[]
        try:
            dpath=os.path.join(verification_dir, f"verify_{secrets.token_hex(16)}_{secure_filename(document.filename)}")
            spath=os.path.join(verification_dir, f"verify_{secrets.token_hex(16)}_{secure_filename(selfie.filename)}")
            document.save(dpath); selfie.save(spath); paths=[dpath,spath]
            result=_ai_identity_precheck(dpath, spath)
            recommendation=result.get("recommendation") if isinstance(result, dict) else "manual_review"
            status="pending"
            if recommendation == "likely_ok": status="ai_passed_pending_manual"
            elif recommendation == "reject_for_quality": status="needs_resubmission"
            with get_conn() as conn:
                conn.execute("UPDATE verification_requests SET status='superseded' WHERE user_id=%s AND status IN ('pending','ai_passed_pending_manual','needs_resubmission')", (g.user["id"],))
                conn.execute("INSERT INTO verification_requests(user_id,status,ai_result,document_sha256,selfie_sha256) VALUES (%s,%s,%s,%s,%s)", (g.user["id"],status,json.dumps(result, ensure_ascii=False),_hash_file(dpath),_hash_file(spath)))
                conn.execute("UPDATE users SET verification_status=%s WHERE id=%s", ('pending' if status != 'needs_resubmission' else 'unverified', g.user["id"]))
                conn.commit()
            flash("تم استلام طلب التحقق. النتيجة النهائية تحتاج مراجعة، والـAI مجرد فحص أولي.", "success")
        except Exception:
            flash("تعذر معالجة طلب التحقق. جرّب صورًا أوضح.", "error")
        finally:
            for path in paths:
                try: os.remove(path)
                except OSError: pass
        return redirect(url_for("verify_identity"))

    def audit(conn, action, target_type=None, target_id=None, metadata=None):
        conn.execute("INSERT INTO audit_logs(actor_id,action,target_type,target_id,metadata) VALUES (%s,%s,%s,%s,%s)", (g.user["id"] if g.user else None, action, target_type, target_id, json.dumps(metadata or {}, ensure_ascii=False)))

    @app.route("/offers/<int:job_id>", methods=["GET", "POST"])
    @login_required
    def offers(job_id):
        with get_conn() as conn:
            job_row = conn.execute("SELECT id,title,user_id,status,price FROM jobs WHERE id=%s", (job_id,)).fetchone()
            if not job_row: abort(404)
            if request.method == "POST":
                if job_row["user_id"] == g.user["id"]:
                    flash("صاحب الشغلة لا يقدر يعمل عرض لنفسه.", "warning")
                    return redirect(url_for("job", job_id=job_id))
                try: amount=int(request.form.get("amount","-1"))
                except ValueError: amount=-1
                note=request.form.get("note","").strip()[:1500]
                if not (0 <= amount <= 10_000_000):
                    flash("قيمة العرض غير صحيحة.","error")
                    return redirect(url_for("job", job_id=job_id))
                conn.execute("UPDATE offers SET status='cancelled',updated_at=now() WHERE job_id=%s AND buyer_id=%s AND status='pending'",(job_id,g.user["id"]))
                conn.execute("INSERT INTO offers(job_id,buyer_id,seller_id,amount,note) VALUES (%s,%s,%s,%s,%s)",(job_id,g.user["id"],job_row["user_id"],amount,note or None))
                conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'offer','عرض جديد',%s,%s)",(job_row["user_id"],f"وصلك عرض جديد بقيمة {amount} جنيه.",url_for("offers",job_id=job_id)))
                audit(conn,"offer_created","job",job_id,{"amount":amount})
                conn.commit(); flash("تم إرسال العرض للبائع.","success")
                return redirect(url_for("job",job_id=job_id))
            rows=conn.execute("SELECT o.*,ub.username buyer_username,us.username seller_username FROM offers o JOIN users ub ON ub.id=o.buyer_id JOIN users us ON us.id=o.seller_id WHERE o.job_id=%s ORDER BY o.created_at DESC",(job_id,)).fetchall()
        return render_template("offers.html",job=job_row,offers=rows)

    @app.post("/offer/<int:offer_id>/decision")
    @login_required
    def offer_decision(offer_id):
        decision=request.form.get("decision")
        if decision not in {"accept","reject","cancel"}: abort(400)
        with get_conn() as conn:
            o=conn.execute("SELECT * FROM offers WHERE id=%s FOR UPDATE",(offer_id,)).fetchone()
            if not o: abort(404)
            if g.user["id"] not in {o["buyer_id"],o["seller_id"]}: abort(403)
            if o["status"]!="pending":
                flash("العرض لم يعد متاحًا.","warning"); return redirect(url_for("offers",job_id=o["job_id"]))
            if decision=="accept":
                if g.user["id"]!=o["seller_id"]: abort(403)
                conn.execute("UPDATE offers SET status='accepted',updated_at=now() WHERE id=%s",(offer_id,))
                order=conn.execute("INSERT INTO orders(job_id,offer_id,buyer_id,seller_id,amount) VALUES (%s,%s,%s,%s,%s) RETURNING id",(o["job_id"],offer_id,o["buyer_id"],o["seller_id"],o["amount"])).fetchone()
                conn.execute("UPDATE offers SET status='rejected',updated_at=now() WHERE job_id=%s AND id<>%s AND status='pending'",(o["job_id"],offer_id))
                conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'order','تم قبول العرض','البائع قبل عرضك. أكمل الدفع لبدء الطلب.',%s)",(o["buyer_id"],url_for("order_detail",order_id=order["id"])))
                audit(conn,"offer_accepted","offer",offer_id,{"order_id":order["id"]})
                flash("تم قبول العرض وإنشاء الطلب.","success")
                target=url_for("order_detail",order_id=order["id"])
            else:
                if decision=="reject" and g.user["id"]!=o["seller_id"]: abort(403)
                if decision=="cancel" and g.user["id"]!=o["buyer_id"]: abort(403)
                conn.execute("UPDATE offers SET status=%s,updated_at=now() WHERE id=%s",("rejected" if decision=="reject" else "cancelled",offer_id))
                audit(conn,"offer_"+decision,"offer",offer_id)
                target=url_for("offers",job_id=o["job_id"]); flash("تم تحديث العرض.","success")
            conn.commit()
        return redirect(target)

    @app.get("/orders")
    @login_required
    def orders():
        with get_conn() as conn:
            rows=conn.execute("SELECT o.*,j.title,ub.username buyer_username,us.username seller_username FROM orders o JOIN jobs j ON j.id=o.job_id JOIN users ub ON ub.id=o.buyer_id JOIN users us ON us.id=o.seller_id WHERE o.buyer_id=%s OR o.seller_id=%s ORDER BY o.created_at DESC",(g.user["id"],g.user["id"])).fetchall()
        return render_template("orders.html",orders=rows)

    @app.route("/order/<int:order_id>", methods=["GET"])
    @login_required
    def order_detail(order_id):
        with get_conn() as conn:
            order=conn.execute("SELECT o.*,j.title,j.user_id,ub.username buyer_username,us.username seller_username FROM orders o JOIN jobs j ON j.id=o.job_id JOIN users ub ON ub.id=o.buyer_id JOIN users us ON us.id=o.seller_id WHERE o.id=%s",(order_id,)).fetchone()
            if not order: abort(404)
            if g.user["id"] not in {order["buyer_id"],order["seller_id"]}: abort(403)
            disputes=conn.execute("SELECT d.*,u.username FROM disputes d JOIN users u ON u.id=d.opened_by WHERE d.order_id=%s ORDER BY d.created_at DESC",(order_id,)).fetchall()
        return render_template("order.html",order=order,disputes=disputes)

    @app.post("/order/<int:order_id>/status")
    @login_required
    def order_status(order_id):
        status=request.form.get("status")
        allowed={"in_progress","delivered","completed","cancelled"}
        if status not in allowed: abort(400)
        with get_conn() as conn:
            o=conn.execute("SELECT * FROM orders WHERE id=%s FOR UPDATE",(order_id,)).fetchone()
            if not o or g.user["id"] not in {o["buyer_id"],o["seller_id"]}: abort(403)
            if status=="in_progress" and g.user["id"]!=o["buyer_id"]: abort(403)
            if status=="delivered" and g.user["id"]!=o["seller_id"]: abort(403)
            if status=="completed" and g.user["id"]!=o["buyer_id"]: abort(403)
            if status=="cancelled" and o["status"] not in {"pending_payment","in_progress"}: abort(400)
            if status=="completed" and o["payment_status"]!="paid":
                flash("لا يمكن إنهاء الطلب قبل تسجيل الدفع كمدفوع.","warning"); return redirect(url_for("order_detail",order_id=order_id))
            conn.execute("UPDATE orders SET status=%s,updated_at=now(),completed_at=CASE WHEN %s='completed' THEN now() ELSE completed_at END WHERE id=%s",(status,status,order_id))
            audit(conn,"order_status","order",order_id,{"status":status})
            conn.commit(); flash("تم تحديث حالة الطلب.","success")
        return redirect(url_for("order_detail",order_id=order_id))

    @app.post("/order/<int:order_id>/payment-demo")
    @login_required
    def payment_demo(order_id):
        if free_launch_mode or not env_bool("ENABLE_DEMO_PAYMENTS", False): abort(404)
        with get_conn() as conn:
            o=conn.execute("SELECT * FROM orders WHERE id=%s",(order_id,)).fetchone()
            if not o or o["buyer_id"]!=g.user["id"]: abort(403)
            conn.execute("UPDATE orders SET payment_status='paid',payment_ref=%s,status='in_progress',updated_at=now() WHERE id=%s",("DEMO-"+secrets.token_hex(6),order_id))
            conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'payment','تم الدفع','تم تسجيل دفع تجريبي للطلب.',%s)",(o["seller_id"],url_for("order_detail",order_id=order_id)))
            audit(conn,"demo_payment","order",order_id)
            conn.commit()
        flash("تم تسجيل الدفع التجريبي. استخدم بوابة دفع حقيقية قبل الإطلاق.","success")
        return redirect(url_for("order_detail",order_id=order_id))

    @app.post("/order/<int:order_id>/dispute")
    @login_required
    def open_dispute(order_id):
        reason=request.form.get("reason","").strip()[:2000]
        if len(reason)<10: flash("اكتب سببًا أوضح للنزاع.","error"); return redirect(url_for("order_detail",order_id=order_id))
        with get_conn() as conn:
            o=conn.execute("SELECT * FROM orders WHERE id=%s",(order_id,)).fetchone()
            if not o or g.user["id"] not in {o["buyer_id"],o["seller_id"]}: abort(403)
            conn.execute("INSERT INTO disputes(order_id,opened_by,reason) VALUES (%s,%s,%s)",(order_id,g.user["id"],reason))
            audit(conn,"dispute_opened","order",order_id)
            conn.commit()
        flash("تم فتح النزاع وسيظهر للإدارة.","success")
        return redirect(url_for("order_detail",order_id=order_id))

    @app.post("/ai/job-helper")
    @login_required
    def ai_job_helper():
        if not ai_assistant_enabled or not os.getenv("OPENAI_API_KEY"): return jsonify(error="AI غير مفعّل"),503
        raw=request.form.get("idea","").strip()[:2000]
        if len(raw)<10: return jsonify(error="اكتب فكرة الشغلة أولًا"),400
        prompt=("أنت مساعد لمنصة خدمات عربية. حوّل فكرة المستخدم إلى اقتراح إعلان خدمة واضح. "
                "أعد JSON فقط بالمفاتيح title,description,category,price_suggestion. لا تطلب أو تستنتج بيانات شخصية حساسة. "
                "العملة جنيه مصري. لا تدّعي أن السعر دقيق. الفكرة: "+raw)
        try:
            r=requests.post(ai_assistant_endpoint,headers={"Authorization":"Bearer "+os.environ["OPENAI_API_KEY"],"Content-Type":"application/json"},json={"model":ai_assistant_model,"input":prompt},timeout=45)
            r.raise_for_status(); data=r.json(); text=data.get("output_text","")
            if not text:
                for item in data.get("output",[]):
                    for c in item.get("content",[]):
                        if c.get("type") in {"output_text","text"}: text+=c.get("text","")
            result=json.loads(text)
            return jsonify(result)
        except Exception:
            return jsonify(error="تعذر تشغيل مساعد AI الآن"),502

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    @app.get("/terms")
    def terms():
        return render_template("terms.html")

    @app.get("/admin")
    @login_required
    def admin_dashboard():
        if not is_admin(g.user): abort(403)
        with get_conn() as conn:
            users=conn.execute("SELECT id,username,email,verification_status,is_suspended,created_at FROM users ORDER BY created_at DESC LIMIT 100").fetchall()
            verifications=conn.execute("SELECT v.*,u.username,u.email FROM verification_requests v JOIN users u ON u.id=v.user_id WHERE v.status IN ('pending','ai_passed_pending_manual','needs_resubmission') ORDER BY v.created_at ASC LIMIT 100").fetchall()
            reports=conn.execute("SELECT r.*,u.username AS reporter,j.title FROM reports r JOIN users u ON u.id=r.reporter_id LEFT JOIN jobs j ON j.id=r.job_id WHERE r.status='open' ORDER BY r.created_at ASC LIMIT 100").fetchall()
            counts=conn.execute("SELECT (SELECT COUNT(*) FROM users)::int users,(SELECT COUNT(*) FROM jobs)::int jobs,(SELECT COUNT(*) FROM reports WHERE status='open')::int reports,(SELECT COUNT(*) FROM verification_requests WHERE status IN ('pending','ai_passed_pending_manual'))::int verifications").fetchone()
        return render_template("admin.html", users=users, verifications=verifications, reports=reports, counts=counts)

    @app.post("/admin/user/<int:user_id>/suspend")
    @login_required
    def admin_suspend(user_id):
        if not is_admin(g.user): abort(403)
        if user_id == g.user["id"]: abort(400)
        with get_conn() as conn:
            row=conn.execute("SELECT is_suspended FROM users WHERE id=%s",(user_id,)).fetchone()
            if not row: abort(404)
            new_state=not row["is_suspended"]
            conn.execute("UPDATE users SET is_suspended=%s WHERE id=%s",(new_state,user_id))
            conn.execute("INSERT INTO moderation_actions(admin_id,target_user_id,action,note) VALUES (%s,%s,%s,%s)",(g.user["id"],user_id,"suspend" if new_state else "unsuspend","تمت المراجعة من لوحة الإدارة"))
            conn.commit()
        flash("تم تحديث حالة المستخدم.","success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/verification/<int:verification_id>")
    @login_required
    def admin_verification(verification_id):
        if not is_admin(g.user): abort(403)
        decision=request.form.get("decision")
        if decision not in {"verify","reject"}: abort(400)
        with get_conn() as conn:
            row=conn.execute("SELECT user_id FROM verification_requests WHERE id=%s",(verification_id,)).fetchone()
            if not row: abort(404)
            status="verified" if decision=="verify" else "rejected"
            conn.execute("UPDATE verification_requests SET status=%s,reviewed_at=now(),reviewer_id=%s WHERE id=%s",(status,g.user["id"],verification_id))
            conn.execute("UPDATE users SET verification_status=%s,verified_at=CASE WHEN %s='verified' THEN now() ELSE NULL END,trust_score=CASE WHEN %s='verified' THEN GREATEST(trust_score,50) ELSE trust_score END WHERE id=%s",(status,status,status,row["user_id"]))
            conn.execute("INSERT INTO notifications(user_id,kind,title,body,url) VALUES (%s,'verification','تحديث التحقق',%s,%s)",(row["user_id"],"تم قبول طلب التحقق." if decision=="verify" else "تم رفض طلب التحقق ويُرجى إعادة الإرسال بصور أوضح.",url_for("verify_identity")))
            conn.commit()
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/report/<int:report_id>")
    @login_required
    def admin_report(report_id):
        if not is_admin(g.user): abort(403)
        status=request.form.get("status")
        if status not in {"resolved","dismissed"}: abort(400)
        note=request.form.get("note","").strip()[:1000]
        with get_conn() as conn:
            conn.execute("UPDATE reports SET status=%s,admin_note=%s WHERE id=%s",(status,note,report_id))
            conn.commit()
        return redirect(url_for("admin_dashboard"))

    @app.get("/api/stats")
    def api_stats():
        with get_conn() as conn:
            row=conn.execute("SELECT (SELECT COUNT(*) FROM users)::int users,(SELECT COUNT(*) FROM jobs)::int jobs,(SELECT COUNT(*) FROM users WHERE verification_status='verified')::int verified_users").fetchone()
        return jsonify(row)

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="الصفحة اللي بتدور عليها مش موجودة."), 404

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, message=getattr(e, "description", "الطلب غير صالح.")), 400

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500, message="حصل خطأ غير متوقع. جرّب تاني بعد شوية."), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
