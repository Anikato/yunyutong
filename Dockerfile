# ── 构建阶段 ─────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# 安装 build 依赖（编译 cryptography 等 C 扩展）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
    && pip install --no-cache-dir --prefix=/install gunicorn


# ── 运行阶段 ─────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="云域通 YunYuTong" \
      org.opencontainers.image.description="多平台 DNS 域名管理工具" \
      org.opencontainers.image.source="https://github.com/Anikato/yunyutong"

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制已安装的包
COPY --from=builder /install /usr/local

# 复制应用代码（排除开发/本地文件）
COPY app/        ./app/
COPY config.py   run.py   manage_user.py   migrate_db.py   ./

# 创建数据目录和日志目录（挂载卷用）
RUN mkdir -p /app/data /app/logs

# 数据库默认路径指向 /app/data 目录，方便通过 volume 持久化
ENV DATABASE_URL=sqlite:////app/data/yunyutong.db \
    FLASK_ENV=production \
    FLASK_DEBUG=0

EXPOSE 5000

# 使用 gunicorn 启动，workers 数量可通过环境变量覆盖
ENV GUNICORN_WORKERS=2

CMD ["sh", "-c", "gunicorn --workers ${GUNICORN_WORKERS} --bind 0.0.0.0:5000 --timeout 120 --access-logfile - --error-logfile - run:app"]
