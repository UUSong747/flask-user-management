# Flask 用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0%2B-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

> **安全教学演示项目** — 同一套代码的「漏洞版本」与「安全加固版本」对比，用于 Web 安全教学与代码审计演练。

---

## 目录

- [项目概述](#项目概述)
- [快速开始](#快速开始)
- [分支说明](#分支说明)
- [漏洞清单](#漏洞清单)
- [安全加固要点](#安全加固要点)
- [环境变量配置](#环境变量配置)
- [项目结构](#项目结构)
- [许可证](#许可证)

---

## 项目概述

本项目是一个基于 Python Flask 框架的简易用户信息管理平台，提供用户登录、信息展示、登出等基础功能。

项目包含两个版本：

| 版本 | 分支/标签 | 说明 |
|------|-----------|------|
| **漏洞版本** | `vulnerable`（标签） | 原始代码，故意包含 11 个安全漏洞 |
| **安全加固版** | `main`（默认分支） | 修复全部漏洞后的安全版本 |

通过 `git checkout` 切换版本，对比学习 Web 安全知识。

---

## 快速开始

### 前置条件

- Python 3.8+
- pip

### 安装与运行

```bash
# 克隆仓库
git clone https://github.com/UUSong747/flask-user-management.git
cd flask-user-management

# 安装依赖
pip install flask flask-limiter flask-wtf werkzeug

# 启动服务（默认运行安全加固版）
python app.py
```

访问 `http://127.0.0.1:5000`

### 默认账号

| 用户名 | 密码 | 角色 | 说明 |
|--------|------|------|------|
| `admin` | `admin123` | 管理员 | 拥有全部权限 |
| `alice` | `alice2025` | 普通用户 | 有限权限 |

> ⚠️ **注意**：漏洞版本中密码以 **明文** 存储；安全加固版使用 **scrypt 加盐哈希** 存储。

---

## 分支说明

### 查看漏洞版本

```bash
git checkout vulnerable
python app.py
```

此版本包含 11 个安全漏洞，供安全测试和学习使用。

### 切回安全版本

```bash
git checkout main
python app.py
```

---

## 漏洞清单

漏洞版本（`vulnerable` 标签）共包含以下 11 项安全漏洞：

| 编号 | 漏洞名称 | 风险等级 | CWE |
|------|----------|----------|-----|
| VULN-01 | 明文密码存储 | 🔴 严重 | CWE-312 |
| VULN-02 | 密码明文展示在前端 | 🔴 严重 | CWE-200 |
| VULN-03 | HTML 注释泄露管理员账号 | 🔴 严重 | CWE-540 |
| VULN-04 | Debug 模式对外暴露 | 🔴 严重 | CWE-215 |
| VULN-05 | Secret Key 硬编码弱密钥 | 🟠 高危 | CWE-321 |
| VULN-06 | 无暴力破解防护 | 🟠 高危 | CWE-307 |
| VULN-07 | 无 HTTPS 传输 | 🟠 高危 | CWE-319 |
| VULN-08 | Session 无过期时间 | 🟠 高危 | CWE-613 |
| VULN-09 | 无 CSRF 防护 | 🟡 中危 | CWE-352 |
| VULN-10 | 敏感信息过度暴露 | 🟡 中危 | CWE-200 |
| VULN-11 | 时序侧信道攻击 | 🟡 中危 | CWE-208 |

---

## 安全加固要点

| 漏洞 | 修复方案 |
|------|----------|
| 明文密码 | `werkzeug.security.generate_password_hash()` scrypt 加盐哈希 |
| 密码展示 | 服务端 `safe_user_info()` 过滤 + 模板删除密码行 |
| 凭据泄露 | 删除 HTML 注释，调试信息仅输出至服务端日志 |
| Debug 模式 | 环境变量 `FLASK_DEBUG` 控制，默认关闭；监听默认 `127.0.0.1` |
| 弱密钥 | 优先读取环境变量 `SECRET_KEY`，否则 `os.urandom(32).hex()` |
| 暴力破解 | `Flask-Limiter` 限制 10 次/分钟/IP |
| 明文传输 | 配置项 `SESSION_COOKIE_SECURE`，配合 Nginx 反向代理 HTTPS |
| Session 永不过期 | 30 分钟过期 + `HTTPOnly` + `SameSite=Lax` |
| CSRF | `Flask-WTF` 全局 CSRF 保护 |
| 余额暴露 | 模板中 `{% if user.role == "admin" %}` 权限控制 |
| 时序攻击 | 用户不存在时执行 dummy 哈希比对 |

---

## 环境变量配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `SECRET_KEY` | 自动随机生成 | Session 签名密钥，生产环境务必设置 |
| `FLASK_DEBUG` | `false` | 设为 `true` 启用 Debug 模式 |
| `FLASK_HOST` | `127.0.0.1` | 监听地址，`0.0.0.0` 监听所有网卡 |
| `FLASK_PORT` | `5000` | 监听端口 |
| `HTTPS_ENABLED` | `false` | 设为 `true` 启用 Secure Cookie（需 HTTPS） |

### 生产环境配置示例

```bash
export SECRET_KEY="$(python3 -c 'import os; print(os.urandom(32).hex())')"
export FLASK_HOST="0.0.0.0"
export HTTPS_ENABLED="true"
python app.py
```

---

## 项目结构

```
flask-user-management/
├── app.py                          # 主应用 — Flask 路由与业务逻辑
├── requirements.txt                # Python 依赖清单
├── .gitignore                      # Git 忽略规则
├── README.md                       # 项目说明文档
├── templates/
│   ├── base.html                   # 基础模板（导航栏 + 布局）
│   ├── index.html                  # 首页（用户信息展示）
│   └── login.html                  # 登录页（表单 + CSRF Token）
├── static/
│   └── css/
│       └── style.css               # 全局样式表
├── 安全审计报告_Flask用户管理系统.docx  # 漏洞审计报告
└── 安全加固报告_Flask用户管理系统.docx  # 安全加固报告
```

---

## 许可证

本项目基于 MIT 许可证开源，仅供安全教学与学习研究使用。

**免责声明：** 本项目中的漏洞版本包含已知安全漏洞，仅限在受控环境中用于安全教学。请勿将漏洞版本部署到生产环境或公共网络。使用者需自行承担所有责任。
