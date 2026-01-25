# 云域通 (YunYuTong)

![Python](https://img.shields.io/badge/Python-3.x-blue.svg) ![Flask](https://img.shields.io/badge/Flask-2.x-green.svg) ![Bootstrap](https://img.shields.io/badge/Bootstrap-5.x-purple.svg)

一个基于 Python Flask 的**多平台域名及 DNS 记录管理工具**，支持 Cloudflare、阿里云等主流 DNS 服务商。

## 主要功能

- **多平台支持:** 
  - Cloudflare - 使用 API Token
  - 阿里云 DNS - 使用 AccessKey
  - 易于扩展的 Provider 架构，可轻松添加更多服务商
- **用户认证:** 支持用户注册、登录、登出和密码修改
- **凭证管理:** 安全添加、存储（加密）和管理各平台的 API 凭证
- **域名同步:** 自动从各平台同步域名列表
- **DNS 记录管理:** 查看、添加、编辑、删除 DNS 记录（支持批量删除）
- **界面:** 基于 Bootstrap 5 的简洁响应式界面

## 技术栈

- **后端:** Python 3, Flask, SQLAlchemy
- **凭证加密:** Fernet (cryptography)
- **DNS API:** Cloudflare API v4, 阿里云 DNS API
- **前端:** Bootstrap 5, Jinja2

## 安装与运行

### 1. 克隆并安装依赖

```bash
git clone https://github.com/Anikato/yunyutong.git
cd yunyutong
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 配置环境变量

创建 `.env` 文件：

```env
FLASK_ENV=development
SECRET_KEY=你的随机密钥
ENCRYPTION_KEY=你的加密密钥
```

生成密钥：

```bash
python -c 'import secrets; print(secrets.token_hex(16))'
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

### 3. 运行

```bash
python run.py
```

访问 http://127.0.0.1:5000

## 数据库迁移

如果从旧版本升级：

```bash
python migrate_db.py
```

## 添加新的 DNS Provider

1. 在 `app/providers/` 创建新文件
2. 继承 `DNSProvider` 基类
3. 在 `app/providers/__init__.py` 注册

## 安全说明

- API 凭证使用 Fernet 加密存储
- 用户密码使用 PBKDF2-SHA256 哈希
- 生产环境必须设置 ENCRYPTION_KEY

## 许可证

MIT License
