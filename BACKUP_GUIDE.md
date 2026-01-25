# 云域通 (YunYuTong) 备份与迁移指南

## 📋 概述

本文档说明如何备份和迁移云域通系统的数据。

---

## 🔴 必须备份的文件

| 文件 | 说明 | 重要性 |
|------|------|--------|
| `yunyutong.db` | SQLite 数据库，包含所有用户数据 | ⭐⭐⭐ 极重要 |
| `.env` | 环境配置文件，包含加密密钥 | ⭐⭐⭐ 极重要 |

### ⚠️ 重要警告

- **`ENCRYPTION_KEY`** 用于加密存储的 API 凭证
- 如果丢失此密钥，**所有已保存的 API Token 将无法解密**
- 请务必妥善保管 `.env` 文件

---

## 🟡 可选备份的文件

| 文件/目录 | 说明 |
|-----------|------|
| `logs/` | 应用日志，用于问题排查 |

---

## 🟢 无需备份的文件

| 文件/目录 | 原因 |
|-----------|------|
| `venv/` | 虚拟环境，可通过 `pip install -r requirements.txt` 重建 |
| `__pycache__/` | Python 缓存，自动生成 |
| `*.pyc` | Python 编译文件，自动生成 |
| 源代码文件 | 可从 GitHub 重新克隆 |

---

## 💾 备份操作

### 方法一：快速备份（推荐）

```bash
# 进入项目目录
cd /data/yunyutong

# 创建带日期的备份文件
tar -czvf yunyutong-backup-$(date +%Y%m%d-%H%M%S).tar.gz yunyutong.db .env

# 备份文件示例: yunyutong-backup-20260125-143000.tar.gz
```

### 方法二：完整备份（包含日志）

```bash
cd /data/yunyutong

tar -czvf yunyutong-full-backup-$(date +%Y%m%d).tar.gz \
    yunyutong.db \
    .env \
    logs/
```

### 方法三：仅备份数据库

```bash
# 使用 SQLite 工具导出（更安全，避免写入冲突）
sqlite3 yunyutong.db ".backup 'yunyutong-backup.db'"

# 或直接复制（建议先停止服务）
cp yunyutong.db yunyutong-backup-$(date +%Y%m%d).db
```

---

## 🔄 定时自动备份

### 使用 Cron 定时任务

```bash
# 编辑 crontab
crontab -e

# 添加以下行（每天凌晨 3 点备份）
0 3 * * * cd /data/yunyutong && tar -czvf /backup/yunyutong-$(date +\%Y\%m\%d).tar.gz yunyutong.db .env

# 保留最近 7 天的备份（可选）
0 4 * * * find /backup -name "yunyutong-*.tar.gz" -mtime +7 -delete
```

### 备份脚本示例

创建 `/data/yunyutong/backup.sh`：

```bash
#!/bin/bash
# 云域通自动备份脚本

# 配置
APP_DIR="/data/yunyutong"
BACKUP_DIR="/backup/yunyutong"
KEEP_DAYS=7

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 生成备份文件名
BACKUP_FILE="$BACKUP_DIR/yunyutong-$(date +%Y%m%d-%H%M%S).tar.gz"

# 执行备份
cd "$APP_DIR"
tar -czvf "$BACKUP_FILE" yunyutong.db .env

# 检查备份是否成功
if [ $? -eq 0 ]; then
    echo "✅ 备份成功: $BACKUP_FILE"
    
    # 清理旧备份
    find "$BACKUP_DIR" -name "yunyutong-*.tar.gz" -mtime +$KEEP_DAYS -delete
    echo "🗑️  已清理 $KEEP_DAYS 天前的旧备份"
else
    echo "❌ 备份失败!"
    exit 1
fi
```

使用方法：
```bash
chmod +x backup.sh
./backup.sh
```

---

## 🚚 迁移到新服务器

### 步骤 1：在旧服务器上备份

```bash
cd /data/yunyutong
tar -czvf yunyutong-migrate.tar.gz yunyutong.db .env
```

### 步骤 2：传输到新服务器

```bash
# 使用 scp
scp yunyutong-migrate.tar.gz user@new-server:/tmp/

# 或使用 rsync
rsync -avz yunyutong-migrate.tar.gz user@new-server:/tmp/
```

### 步骤 3：在新服务器上部署

```bash
# 克隆代码
git clone https://github.com/Anikato/yunyutong.git /data/yunyutong
cd /data/yunyutong

# 恢复备份数据
tar -xzvf /tmp/yunyutong-migrate.tar.gz

# 安装依赖并部署
sudo bash deploy.sh
```

### 步骤 4：验证

1. 访问新服务器的 Web 界面
2. 使用原有账号登录
3. 检查 API Token 和域名是否正常显示

---

## 🔧 恢复操作

### 从备份恢复

```bash
cd /data/yunyutong

# 停止服务（如果正在运行）
sudo systemctl stop yunyutong

# 解压备份文件
tar -xzvf yunyutong-backup-XXXXXXXX.tar.gz

# 重启服务
sudo systemctl start yunyutong
```

### 恢复到全新安装

```bash
# 1. 克隆代码
git clone https://github.com/Anikato/yunyutong.git /data/yunyutong
cd /data/yunyutong

# 2. 恢复数据文件
tar -xzvf /path/to/yunyutong-backup.tar.gz

# 3. 部署
sudo bash deploy.sh
```

---

## 🐳 Docker 部署的备份

如果使用 Docker 部署，数据文件位于映射的卷目录：

```bash
# 备份
docker compose stop
tar -czvf backup.tar.gz ./data .env
docker compose start

# 恢复
tar -xzvf backup.tar.gz
docker compose up -d
```

---

## ❓ 常见问题

### Q: 忘记备份 `.env` 文件怎么办？

A: 如果丢失 `ENCRYPTION_KEY`：
- 已保存的 API Token 将无法解密
- 需要重新添加所有 API 凭证
- 用户账号和其他数据不受影响

### Q: 数据库文件损坏怎么办？

A: 尝试使用 SQLite 工具修复：
```bash
sqlite3 yunyutong.db "PRAGMA integrity_check;"
sqlite3 yunyutong.db ".recover" | sqlite3 yunyutong-recovered.db
```

### Q: 如何迁移到 PostgreSQL/MySQL？

A: 
1. 修改 `.env` 中的 `DATABASE_URL`
2. 使用数据库迁移工具导出/导入数据
3. 或重新添加用户和 Token（推荐小规模部署）

---

## 📝 备份检查清单

- [ ] `yunyutong.db` 已备份
- [ ] `.env` 已备份
- [ ] 备份文件已传输到安全位置（异地/云存储）
- [ ] 定期测试备份恢复流程
- [ ] 设置自动备份任务

---

## 🔐 安全建议

1. **加密备份文件**
   ```bash
   # 加密
   gpg -c yunyutong-backup.tar.gz
   
   # 解密
   gpg yunyutong-backup.tar.gz.gpg
   ```

2. **异地备份** - 将备份文件存储到云存储（如阿里云 OSS、AWS S3）

3. **权限控制** - 确保备份文件权限为 600
   ```bash
   chmod 600 yunyutong-backup.tar.gz
   ```

4. **定期验证** - 每月至少进行一次备份恢复测试
