# 云域通 (YunYuTong)

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![Flask](https://img.shields.io/badge/Flask-2.x-green.svg) ![Bootstrap](https://img.shields.io/badge/Bootstrap-5.x-purple.svg)

一个基于 Python Flask 和 Cloudflare API 的简单域名及 DNS 记录管理工具。

## ✨ 主要功能

*   **用户认证:** 支持用户注册、登录、登出和密码修改。
*   **Cloudflare API Token 管理:**
    *   安全添加、存储（加密）和管理 Cloudflare API Tokens。
    *   自动验证 Token 有效性及所需权限（Zone Read, DNS Read/Write）。
    *   首页预览每个 Token 下的域名。
*   **域名同步:**
    *   根据有效的 API Token 自动从 Cloudflare 同步用户有权限访问的域名列表到本地数据库。
*   **DNS 记录管理:**
    *   查看指定域名的 DNS 记录列表（支持分页）。
    *   添加新的 DNS 记录（支持 A, AAAA, CNAME, TXT, MX, SRV, NS 等类型，自动内容校验）。
    *   编辑现有 DNS 记录（名称、内容、TTL、代理状态等）。
    *   删除 DNS 记录。
    *   自动同步 DNS 记录到本地数据库。
*   **界面:** 基于 Bootstrap 5 和 Bootswatch (Litera 主题) 的简洁响应式界面。

*(未来可以考虑在此处添加应用截图)*

## 🚀 技术栈

*   **后端:** Python 3, Flask
*   **数据库:** SQLAlchemy, Flask-Migrate (用于数据库迁移), SQLite (默认)
*   **表单处理:** Flask-WTF
*   **用户认证:** Flask-Login, Werkzeug (密码哈希)
*   **前端:** HTML, Bootstrap 5, Bootswatch (Litera), Jinja2
*   **WSGI 服务器 (推荐):** Gunicorn 或 Waitress
*   **部署 (示例):** Nginx, Systemd

## 本地运行与设置

按照以下步骤在你的本地机器上设置并运行"云域通"。

### 1. 克隆仓库

```bash
git clone https://github.com/Anikato/yunyutong.git
cd yunyutong
```

### 2. 创建并激活 Python 虚拟环境

强烈建议使用虚拟环境来隔离项目依赖。

```bash
# 创建虚拟环境 (例如命名为 venv)
python3 -m venv venv

# 激活虚拟环境
# macOS / Linux:
source venv/bin/activate
# Windows:
# venv\Scripts\activate
```

### 3. 安装依赖

使用 `requirements.txt` 文件安装所有必需的 Python 包。

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量 (重要!)

应用需要一些配置才能运行，尤其是 `SECRET_KEY`。你可以通过创建 `.env` 文件或直接设置环境变量来提供这些配置。

**推荐方式：创建 `.env` 文件**

在项目根目录下创建一个名为 `.env` 的文件（**注意：** 此文件已在 `.gitignore` 中，不会上传到 Git），并填入以下内容：

```env
# Flask 配置
FLASK_APP=app.py
FLASK_ENV=development # 本地开发设为 development
# SECRET_KEY=一个非常复杂且随机的字符串 # 必须设置！用于会话安全等
# DATABASE_URL=sqlite:///yunyutong.db # 数据库连接URL (默认使用 SQLite)

# 其他可选配置...
```

**生成 SECRET_KEY:** 你可以使用 Python 生成一个安全的密钥：
```bash
python -c 'import secrets; print(secrets.token_hex(16))'
```
将生成的随机字符串填入 `.env` 文件。

### 5. 初始化/更新数据库

首次运行时，需要创建数据库表。如果模型有更新，也需要应用迁移。

```bash
# 如果是首次设置，可能需要初始化 Flask-Migrate (如果还没做)
# flask db init

# 生成数据库迁移脚本 (如果模型有更改)
# flask db migrate -m "一些描述信息"

# 应用数据库迁移 (创建表或更新表结构)
flask db upgrade
```

### 6. 运行应用 (使用 Waitress)

我们推荐使用 Waitress (或其他 WSGI 服务器) 而不是 Flask 开发服务器。

```bash
# 监听在 8000 端口
waitress-serve --host 0.0.0.0 --port 8000 app:app
```

然后，在浏览器中访问 `http://127.0.0.1:8000`。

## 部署到生产环境

有关如何在生产环境服务器上部署此应用的详细说明（使用 Gunicorn, Nginx, Systemd），请参阅 [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md)。

## 🤝 贡献 (可选)

欢迎提出改进建议或报告问题！你可以通过 GitHub Issues 来进行。

## 📄 许可证 (可选)

*(如果选择，可以在此说明项目使用的许可证，例如 MIT License)* 