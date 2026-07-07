"""用户信息管理平台 - 安全加固版本"""
import os
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
    # 密钥管理：优先使用环境变量，否则自动生成随机密钥
    SECRET_KEY=os.environ.get(
        "SECRET_KEY",
        os.urandom(32).hex()
    ),
    # Session 过期时间：30 分钟
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    # Session Cookie 安全选项
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # 生产环境启用 Secure Cookie（需要 HTTPS）
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower() == "true",
    # 关闭 Debug 模式，由环境变量控制
    DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
)

# CSRF 保护（Flask-WTF）
csrf = CSRFProtect(app)

# 请求频率限制（Flask-Limiter）
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── 用户数据库 ──
# 密码经过加盐哈希存储，不再使用明文
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

        # 恒定时间密码比对（无论用户是否存在，都要做比对操作）
        if user is None:
            # 使用 dummy 哈希防止时序攻击
            check_password_hash(
                "scrypt:32768:8:1$dummy_salt$dummy_hash",
                password
            )
            return render_template("login.html", error="用户名或密码错误，请重试")

        if check_password_hash(user["password"], password):
            # 设置 session
            session.permanent = True
            session["username"] = username
            session["role"] = user["role"]
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="用户名或密码错误，请重试")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # 从环境变量读取主机和端口，有安全默认值
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    print(f"  → 服务启动: http://{host}:{port}")
    print(f"  → Debug 模式: {'ON' if debug else 'OFF'}")
    print(f"  → Session 过期: 30 分钟")
    print(f"  → 登录频率限制: 10 次/分钟/IP")
    print(f"  → CSRF 保护: 已启用")
    print(f"  → 密码存储: 加盐哈希 (scrypt)")
    print("=" * 50)

    app.run(debug=debug, host=host, port=port)
