# "云域通" Flask 应用生产环境部署指南 (Ubuntu/Debian + Gunicorn + Nginx + Systemd)

本文档指导你如何将基于 Flask 开发的"云域通"应用部署到生产环境服务器。

**部署架构概览:**

```
用户请求 --> Nginx (处理 HTTPS, 静态文件, 反向代理) --> Gunicorn (运行 Flask 应用) --> Flask 应用 (云域通)
         ^                                                    |
         |---------------- Systemd (管理 Gunicorn 进程) ------|
```

**假设:**

*   你已经有了一台可以访问的 Linux 服务器（例如 Ubuntu 20.04/22.04）。
*   你拥有服务器的 root 或 sudo 权限。
*   你已经将你的域名（例如 `yunyutong.yourdomain.com`）解析到了服务器的公网 IP 地址。

**步骤:**

### 1. 服务器准备与基础软件安装

首先，更新系统并安装必要的软件包：Python 3, pip, venv（用于创建虚拟环境）和 Nginx。

```bash
sudo apt update
sudo apt upgrade -y # 可选，但建议更新
sudo apt install -y python3 python3-pip python3-venv nginx
```

### 2. 获取应用程序代码

将你的"云域通"项目代码部署到服务器。推荐使用 Git。

```bash
# 示例：假设你的代码放在 GitHub
# git clone <你的仓库地址> /home/<你的用户名>/YunYuTong
# 或者，如果你是手动上传的，确保代码在服务器上的某个路径，例如 /home/<你的用户名>/YunYuTong

# 进入项目目录 (请替换为实际路径)
cd /home/<你的用户名>/YunYuTong 
# 后续所有 /path/to/yourproject 都应替换为此路径
```

### 3. 配置 Python 虚拟环境

为应用创建一个独立的 Python 虚拟环境，以隔离依赖。

```bash
# 在项目根目录创建虚拟环境，命名为 venv
python3 -m venv venv

# 激活虚拟环境
source venv/bin/activate

# (重要!) 确保项目中有最新的 requirements.txt 文件

# 安装 Gunicorn 和项目依赖
# 确保 requirements.txt 中包含所有必要的库 (Flask, SQLAlchemy, requests, etc.)
pip install gunicorn
pip install -r requirements.txt

# (可选) 测试 waitress 是否也需要安装
# pip install waitress # 如果你打算用 Waitress 而不是 Gunicorn

# 退出虚拟环境（我们稍后会让 Systemd 来激活它）
# deactivate
```

### 4. 配置 Gunicorn (WSGI 服务器)

Gunicorn 将负责运行你的 Flask 应用。我们使用 Systemd 来管理它。

**测试 Gunicorn (可选但推荐):**

在项目目录下，*临时激活虚拟环境* (`source venv/bin/activate`)，然后运行 (替换 `<你的用户名>` 和路径)：

```bash
gunicorn --workers 3 --bind unix:/home/<你的用户名>/YunYuTong/yunyutong.sock -m 007 app:app
```

*   `--workers 3`: 工作进程数。建议 `(2 * CPU核心数) + 1`。
*   `--bind unix:/path/to/yourproject/yunyutong.sock`: 监听 Unix Socket。
*   `-m 007`: 设置 socket 文件权限，允许 Nginx 用户访问。
*   `app:app`: 指定 Flask 应用实例 (`app.py` 中的 `app`)。

如果成功，按 `Ctrl+C` 停止，并删除 `yunyutong.sock` (`rm yunyutong.sock`)。

### 5. 配置 Systemd 服务

创建 Systemd 服务文件来管理 Gunicorn。

```bash
sudo nano /etc/systemd/system/yunyutong.service
```

粘贴以下内容 (**替换** `<你的用户名>` 和项目路径，**并添加环境变量**):

```ini
[Unit]
Description=Gunicorn instance for YunYuTong
After=network.target

[Service]
User=<你的用户名>
Group=www-data 
WorkingDirectory=/home/<你的用户名>/YunYuTong
Environment="PATH=/home/<你的用户名>/YunYuTong/venv/bin"
# (重要!) 在这里设置生产环境变量
Environment="FLASK_ENV=production"
# Environment="SECRET_KEY=你的生产环境密钥"
# Environment="DATABASE_URL=你的生产数据库URL"
# ... 其他需要的环境变量

ExecStart=/home/<你的用户名>/YunYuTong/venv/bin/gunicorn --workers 3 --bind unix:yunyutong.sock -m 007 app:app

Restart=always

[Install]
WantedBy=multi-user.target
```

**权限说明:** 确保 `<你的用户名>` 用户对项目目录有读写权限，`www-data` 组（Nginx 组）能访问 socket。可能需要运行：
`sudo chown -R <你的用户名>:www-data /home/<你的用户名>/YunYuTong`
`sudo chmod -R g+rx /home/<你的用户名>/YunYuTong`

启动并启用服务：

```bash
sudo systemctl start yunyutong
sudo systemctl enable yunyutong
sudo systemctl status yunyutong # 检查状态
# 查看日志: sudo journalctl -u yunyutong
```

### 6. 配置 Nginx (反向代理)

Nginx 处理外部请求，转发动态请求给 Gunicorn，处理静态文件。

```bash
sudo nano /etc/nginx/sites-available/yunyutong
```

粘贴以下配置 (**替换** `yunyutong.yourdomain.com` 和 `<你的用户名>`/路径):

```nginx
server {
    listen 80;
    server_name yunyutong.yourdomain.com www.yunyutong.yourdomain.com;

    location /static {
        alias /home/<你的用户名>/YunYuTong/static;
        expires 30d;
    }

    location / {
        proxy_pass http://unix:/home/<你的用户名>/YunYuTong/yunyutong.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

启用配置并测试：

```bash
sudo ln -s /etc/nginx/sites-available/yunyutong /etc/nginx/sites-enabled/
sudo nginx -t # 测试配置
sudo systemctl restart nginx # 重启 Nginx
```

### 7. 配置防火墙

如果使用 `ufw`：

```bash
sudo ufw allow 'Nginx Full' # 允许 HTTP (80) 和 HTTPS (443)
# sudo ufw enable
# sudo ufw status
```

### 8. 完成与验证

*   检查服务状态 (`systemctl status yunyutong`, `systemctl status nginx`)。
*   通过域名访问应用 `http://yunyutong.yourdomain.com`。
*   查看日志 (`/var/log/nginx/error.log`, `journalctl -u yunyutong`) 排查问题。

### 9. (强烈推荐) 配置 HTTPS

使用 Certbot 和 Let's Encrypt 获取免费 SSL 证书。

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yunyutong.yourdomain.com -d www.yunyutong.yourdomain.com # 替换域名
```

Certbot 会自动配置 Nginx 并处理证书续期。完成后，应通过 `https://yunyutong.yourdomain.com` 访问。

---

祝你部署顺利！ 