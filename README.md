# 云域通 (YunYuTong)

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg) ![Flask](https://img.shields.io/badge/Flask-3.x-green.svg) ![Bootstrap](https://img.shields.io/badge/Bootstrap-5.x-purple.svg) ![License](https://img.shields.io/badge/License-MIT-yellow.svg) ![Docker](https://img.shields.io/badge/Docker-l97312%2Fyunyutong-2496ED.svg?logo=docker&logoColor=white)

一个基于 Python Flask 的**多平台域名及 DNS 记录管理工具**，支持 Cloudflare、阿里云等主流 DNS 服务商。

## ✨ 主要功能

- **多平台支持:** 
  - ☁️ Cloudflare - 使用 API Token
  - 🌐 阿里云 DNS - 使用 AccessKey
  - 🔌 易于扩展的 Provider 架构，可轻松添加更多服务商
- **用户认证:** 支持用户注册、登录、登出和密码修改
- **凭证管理:** 安全添加、存储（加密）和管理各平台的 API 凭证
- **域名同步:** 自动从各平台同步域名列表
- **DNS 记录管理:** 查看、添加、编辑、删除 DNS 记录（支持批量删除）
- **搜索筛选:** 支持按名称、内容搜索和按类型筛选 DNS 记录
- **界面:** 基于 Bootstrap 5 的现代化响应式界面，支持深色/浅色模式
- **凭证迁移:** 支持跨服务器导入/导出凭证（密码二次加密保护）

## 🛠️ 技术栈

- **后端:** Python 3.8+, Flask 3.x, SQLAlchemy
- **凭证加密:** Fernet (cryptography)
- **DNS API:** Cloudflare API v4, 阿里云 DNS API
- **前端:** Bootstrap 5 (Bootswatch Litera), Jinja2
- **部署:** Docker / Gunicorn + Nginx + Systemd

## 🚀 快速开始

### 方式一：Docker 部署（推荐）

**最省心的方式，整个目录打包即可迁移。**

**1. 准备部署目录**

```bash
mkdir yunyutong && cd yunyutong

# 下载配置文件
curl -O https://raw.githubusercontent.com/Anikato/yunyutong/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/Anikato/yunyutong/main/env.docker.example
cp env.docker.example .env
```

**2. 生成并填入密钥**

```bash
# 生成 SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# 生成 ENCRYPTION_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

编辑 `.env` 文件，将生成的两个密钥填入对应位置：

```bash
nano .env
```

**3. 启动服务**

```bash
mkdir -p data   # 首次部署需创建数据目录
docker compose up -d
```

**4. 初始化（仅首次）**

```bash
# 创建管理员账号
docker exec -it yunyutong python3 manage_user.py
```

访问 `http://服务器IP:5000`

---

**部署目录结构：**

```
yunyutong/
├── docker-compose.yml   ← Compose 配置
├── .env                 ← 密钥配置（勿提交到 Git）
└── data/
    └── yunyutong.db     ← 数据库（首次启动自动创建）
```

> **迁移到新服务器** 只需打包整个目录：
> ```bash
> # 旧服务器
> tar czf yunyutong-backup.tar.gz yunyutong/
>
> # 新服务器解压后直接启动
> docker compose up -d
> ```

---

### 方式二：一键部署脚本 (Debian/Ubuntu)

```bash
git clone https://github.com/Anikato/yunyutong.git
cd yunyutong
sudo bash deploy.sh
```

脚本会自动完成：安装依赖 → 创建虚拟环境 → 配置环境变量 → 创建 Systemd 服务

### 方式三：手动安装 (开发环境)

```bash
git clone https://github.com/Anikato/yunyutong.git
cd yunyutong

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

cp env.example .env
# 编辑 .env，设置 SECRET_KEY 和 ENCRYPTION_KEY
```

**运行开发服务器：**

```bash
source venv/bin/activate
export FLASK_ENV=development
python3 run.py
```

访问 `http://127.0.0.1:5000`

## 📂 项目结构

```
yunyutong/
├── app/                      # 应用主目录
│   ├── __init__.py          # Flask 应用工厂
│   ├── models.py            # 数据库模型
│   ├── forms.py             # WTForms 表单
│   ├── providers/           # DNS 服务商模块
│   │   ├── base.py         # 基类
│   │   ├── cloudflare.py   # Cloudflare
│   │   └── aliyun.py       # 阿里云
│   ├── routes/              # 路由蓝图
│   │   ├── auth.py         # 认证
│   │   ├── main.py         # 主页
│   │   ├── token.py        # 凭证管理（含导入/导出）
│   │   ├── dns.py          # DNS 记录管理
│   │   └── api.py          # 内部 API（排序等）
│   ├── templates/           # Jinja2 模板
│   └── static/              # 静态资源
├── Dockerfile               # Docker 镜像构建
├── docker-compose.yml       # Docker Compose 部署配置
├── .github/workflows/       # GitHub Actions 自动构建
├── config.py                # 配置文件
├── run.py                   # 启动入口
├── deploy.sh                # 一键部署脚本（传统方式）
├── nginx.conf.example       # Nginx 配置示例
├── env.docker.example       # Docker 环境变量模板
└── requirements.txt         # Python 依赖
```

## ⚙️ 环境配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask 会话签名密钥 | **必须设置** |
| `ENCRYPTION_KEY` | API 凭证加密密钥 (Fernet) | **必须设置** |
| `DATABASE_URL` | 数据库连接字符串 | SQLite（Docker 已预设） |
| `FLASK_ENV` | 环境类型 (`development`/`production`) | `production` |
| `FLASK_DEBUG` | 调试模式 (`0`/`1`) | `0` |
| `GUNICORN_WORKERS` | Gunicorn 工作进程数 | `2` |

> ⚠️ `SECRET_KEY` 和 `ENCRYPTION_KEY` **修改后会导致现有加密数据失效**，请妥善保管并不要随意变更。

## 🔄 数据库迁移

如果从旧版本升级：

```bash
python3 migrate_db.py
```

## 🔌 添加新的 DNS Provider

1. 在 `app/providers/` 创建新文件 (如 `dnspod.py`)
2. 继承 `DNSProvider` 基类，实现抽象方法
3. 在 `app/providers/__init__.py` 注册

```python
# app/providers/dnspod.py
from .base import DNSProvider

class DNSPodProvider(DNSProvider):
    provider_type = 'dnspod'
    display_name = 'DNSPod'
    
    # 实现抽象方法...
```

## 🔒 安全说明

- API 凭证使用 **Fernet 对称加密** 存储
- 用户密码使用 **PBKDF2-SHA256** 哈希
- 生产环境必须设置 `SECRET_KEY` 和 `ENCRYPTION_KEY`
- 建议使用 **HTTPS** 并配置防火墙

## 📋 常用命令

**Docker 方式：**

```bash
docker compose up -d              # 启动（后台）
docker compose down               # 停止
docker compose restart            # 重启
docker compose pull && docker compose up -d  # 更新到最新镜像

docker compose logs -f            # 实时查看日志
docker exec -it yunyutong python3 manage_user.py  # 管理用户
```

**传统 Systemd 方式：**

```bash
sudo systemctl start yunyutong    # 启动
sudo systemctl stop yunyutong     # 停止
sudo systemctl restart yunyutong  # 重启
sudo systemctl status yunyutong   # 状态
sudo journalctl -u yunyutong -f   # 实时日志

sudo bash deploy.sh               # 完整部署
sudo bash deploy.sh --update      # 更新依赖
sudo bash deploy.sh --uninstall   # 卸载服务
```

## 📄 许可证

MIT License
