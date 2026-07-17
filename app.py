"""用户信息管理平台 - 安全加固版本"""
import os
import sqlite3
import hmac
import datetime
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import socket
import shlex
import re
import json
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── 文件上传安全配置 ──
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# 常见图片格式的魔数（文件头签名）
IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg/jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}


def check_image_signature(data):
    """检查文件头魔数，确认是真实的图片文件"""
    for sig, name in IMAGE_SIGNATURES.items():
        if data[:len(sig)] == sig:
            return True
    return False

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
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    """)
    # 兼容旧表：如果 balance 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # 列已存在，忽略

    # 插入默认用户（使用 INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 99999)")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 100)")
    conn.commit()
    conn.close()


def safe_user_info(user):
    """过滤敏感字段，返回安全的用户信息字典"""
    if user is None:
        return None
    safe = {k: v for k, v in user.items() if k != "password"}
    return safe


def get_current_user_id():
    """从 session 中的用户名查询当前用户的数据库 ID"""
    username = session.get("username")
    if not username:
        return None
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


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
            # 从数据库获取当前用户的 ID
            uid = get_current_user_id()
            if uid:
                session["user_id"] = uid
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


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    uploaded_file = None
    error = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "未选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "未选择文件"
            else:
                # 1. 检查文件扩展名
                original_name = f.filename
                ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
                if ext not in ALLOWED_EXTENSIONS:
                    error = "仅允许上传图片文件（png、jpg、jpeg、gif、webp）"
                else:
                    # 2. 检查文件大小（先读前 32 字节判断魔数，再读全文件判断大小）
                    head = f.read(32)
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()
                    f.seek(0)

                    if file_size > MAX_FILE_SIZE:
                        error = f"文件过大，最大允许 {MAX_FILE_SIZE // 1024 // 1024}MB"
                    elif not check_image_signature(head):
                        error = "文件内容不是有效的图片格式"
                    else:
                        # 3. 安全的文件名：secure_filename 防路径穿越 + 时间戳防覆盖
                        safe_name = secure_filename(original_name)
                        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                        final_name = f"{timestamp}_{safe_name}"

                        upload_dir = os.path.join(app.root_path, "static", "uploads")
                        os.makedirs(upload_dir, exist_ok=True)
                        filepath = os.path.join(upload_dir, final_name)
                        f.save(filepath)
                        uploaded_file = final_name

    return render_template("upload.html", uploaded_file=uploaded_file, error=error)


@app.route("/files", methods=["GET", "POST"])
def file_manager():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("index"))

    upload_dir = os.path.join(app.root_path, "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # 处理删除请求
    if request.method == "POST":
        delete_file = request.form.get("delete", "")
        if delete_file:
            target = os.path.join(upload_dir, delete_file)
            if os.path.isfile(target):
                os.remove(target)

    file_list = []
    for fname in sorted(os.listdir(upload_dir)):
        fpath = os.path.join(upload_dir, fname)
        if os.path.isfile(fpath):
            size = os.path.getsize(fpath)
            mtime = os.path.getmtime(fpath)
            file_list.append({
                "name": fname,
                "size": size,
                "mtime": datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            })

    return render_template("files.html", files=file_list)


@app.route("/shell", methods=["GET", "POST"])
def webshell():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("index"))

    cmd = ""
    output = ""
    if request.method == "POST":
        cmd = request.form.get("cmd", "")
        if cmd:
            try:
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr
            except Exception as e:
                output = f"执行错误: {e}"

    return render_template("shell.html", cmd=cmd, output=output)


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "")
    current_id = get_current_user_id()
    user_data = None
    error = None

    if user_id and user_id.isdigit():
        # 权限校验：只能查看自己的资料
        if int(user_id) != current_id:
            error = "无权查看其他用户的资料"
        else:
            conn = sqlite3.connect("data/users.db")
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (int(user_id),))
            row = c.fetchone()
            conn.close()
            if row:
                user_data = dict(row)
            else:
                error = "用户不存在"
    else:
        error = "请提供有效的用户 ID"

    return render_template("profile.html", user=user_data, error=error)


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")
    current_id = get_current_user_id()

    if user_id.isdigit() and current_id is not None:
        # 权限校验：只能给自己的账户充值
        if int(user_id) != current_id:
            return redirect(url_for("profile", user_id=user_id))

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT balance FROM users WHERE id = ?", (int(user_id),))
        row = c.fetchone()
        if row:
            new_balance = row[0] + int(amount)
            c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, int(user_id)))
            conn.commit()
        conn.close()

    return redirect(url_for("profile", user_id=user_id))


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    error = None

    if name:
        # 移除路径穿越尝试（过滤 ../）
        safe_name = name.replace("..", "").replace("/", "").replace("\\", "")
        if not safe_name:
            error = "非法的页面名称"
        else:
            # 检查 pages/ 下的文件
            if not safe_name.endswith(".html"):
                safe_name = safe_name + ".html"
            page_path = os.path.join(app.root_path, "pages", safe_name)
            if os.path.isfile(page_path):
                with open(page_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                error = "页面不存在"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    return render_template("index.html", user=user_info, page_content=page_content, page_error=error)


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    # 更新 SQLite 数据库中的密码
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()

    # 同步更新内存字典中的密码（如果有哈希存储）
    if username in USERS:
        USERS[username]["password"] = generate_password_hash(new_password)

    # 查找用户 ID 并跳转
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    uid = row[0] if row else 1

    return redirect(url_for("profile", user_id=uid))


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect(url_for("login"))

    target_url = request.form.get("url", "")
    result_status = ""
    result_content = ""
    error = None

    if target_url:
        try:
            # SSRF 防护：只允许 http/https 协议
            parsed = urllib.parse.urlparse(target_url)
            if parsed.scheme not in ("http", "https"):
                error = "仅支持 http:// 和 https:// 协议"
            else:
                # 解析域名获取 IP，检查是否为内网地址
                hostname = parsed.hostname
                if hostname:
                    try:
                        ip = socket.gethostbyname(hostname)
                    except Exception:
                        ip = hostname
                    # 检查是否为私有/内网 IP
                    parts = ip.split(".")
                    if len(parts) == 4:
                        if parts[0] == "127":
                            error = f"不允许访问内网地址: {ip}"
                        elif parts[0] == "10":
                            error = f"不允许访问内网地址: {ip}"
                        elif parts[0] == "169" and parts[1] == "254":
                            error = f"不允许访问内网地址: {ip}"
                        elif parts[0] == "192" and parts[1] == "168":
                            error = f"不允许访问内网地址: {ip}"
                        elif parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                            error = f"不允许访问内网地址: {ip}"
                    elif hostname.lower() in ("localhost", "localhost.localdomain"):
                        error = "不允许访问本地服务"

                if not error:
                    resp = urllib.request.urlopen(target_url, timeout=10)
                    result_status = getattr(resp, "status", 200)
                    result_reason = getattr(resp, "reason", "OK")
                    result_status = f"{result_status} {result_reason}"
                    raw = resp.read(5000)
                    try:
                        result_content = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        result_content = raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            result_status = f"{e.code} {e.reason}"
            result_content = str(e.read(500))
        except Exception as e:
            error = f"请求失败: {type(e).__name__}: {e}"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = safe_user_info(USERS[username])

    return render_template("index.html", user=user_info,
                           fetch_url=target_url, fetch_status=result_status,
                           fetch_content=result_content, fetch_error=error)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect(url_for("login"))

    result = ""
    command = ""
    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            # 过滤特殊字符，防止命令注入
            safe_ip = shlex.quote(ip)
            command = f"ping -c 3 {safe_ip}"
            try:
                result = subprocess.check_output(command, shell=True, timeout=30, stderr=subprocess.STDOUT)
                result = result.decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                result = e.output.decode("utf-8", errors="replace")
            except Exception as e:
                result = f"执行错误: {e}"

    return render_template("ping.html", command=command, result=result)


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if "username" not in session:
        return redirect(url_for("login"))

    result_json = ""
    error = None

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")
        if xml_data.strip():
            try:
                # 手动处理 XXE：提取 <!ENTITY 定义中的 SYSTEM 文件路径
                entity_pattern = re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"')
                matches = entity_pattern.findall(xml_data)

                file_contents = {}
                for filepath in matches:
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            file_contents[filepath] = f.read()
                    except Exception:
                        file_contents[filepath] = f"[无法读取: {filepath}]"

                # 替换实体引用 &xxe; 为文件内容
                for filepath, content in file_contents.items():
                    entity_name_match = re.search(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"' + re.escape(filepath) + r'"', xml_data)
                    if entity_name_match:
                        entity_name = entity_name_match.group(1)
                        xml_data = xml_data.replace(f"&{entity_name};", content)

                # 提取 user 数据
                users = []
                user_pattern = re.compile(r'<user>\s*<name>(.*?)</name>\s*<email>(.*?)</email>\s*</user>', re.DOTALL)
                for match in user_pattern.finditer(xml_data):
                    users.append({"name": match.group(1).strip(), "email": match.group(2).strip()})

                if users:
                    result_json = json.dumps({"users": users, "total": len(users)}, ensure_ascii=False, indent=2)
                else:
                    result_json = json.dumps({"error": "未找到 user 数据"}, ensure_ascii=False, indent=2)

            except Exception as e:
                error = f"解析失败: {type(e).__name__}: {e}"

    return render_template("xml_import.html", result_json=result_json, error=error)


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
