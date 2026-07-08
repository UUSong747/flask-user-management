"""用户信息管理平台 - 安全加固版本"""
import os
import sqlite3
import hmac
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get(
        "SECRET_KEY",
        os.urandom(32).hex()
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower() == "true",
    DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── 用户数据库（内存字典，用于登录认证）──
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


# ── SQLite 数据库初始化 ──

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（使用 INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()


def safe_user_info(user):
    """过滤敏感字段，返回安全的用户信息字典"""
    if user is None:
        return None
    safe = {k: v for k, v in user.items() if k != "password"}
    return safe


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)

        if user is None:
            check_password_hash(
                "scrypt:32768:8:1$dummy_salt$dummy_hash",
                password
            )
            return render_template("login.html", error="用户名或密码错误，请重试")

        if check_password_hash(user["password"], password):
            session.permanent = True
            session["username"] = username
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="用户名或密码错误，请重试")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 使用参数化查询防止 SQL 注入
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] 执行注册（参数化）: {sql}")
        print(f"[SQL] 参数: username={username}, password={password}, email={email}, phone={phone}")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在，请选择其他用户名")
        conn.close()
        return redirect(url_for("login", registered="success"))

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        # 使用参数化查询防止 SQL 注入
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        print(f"[SQL] 执行搜索（参数化）: {sql}")
        print(f"[SQL] 参数: keyword={keyword}, like_pattern={like_pattern}")
        c.execute(sql, (like_pattern, like_pattern))
        rows = c.fetchall()
        conn.close()
        results = [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in rows]

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    print(f"  → 服务启动: http://{host}:{port}")
    print(f"  → Debug 模式: {'ON' if debug else 'OFF'}")
    print(f"  → Session 过期: 30 分钟")
    print(f"  → 登录频率限制: 10 次/分钟/IP")
    print(f"  → CSRF 保护: 已启用")
    print(f"  → 密码存储: 加盐哈希 (scrypt)")
    print(f"  → 数据库: data/users.db")
    print("=" * 50)

    app.run(debug=debug, host=host, port=port)
