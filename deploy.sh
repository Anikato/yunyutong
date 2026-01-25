#!/bin/bash

# ============================================
# 云域通 (YunYuTong) 一键部署脚本
# 适用于 Debian / Ubuntu Linux
# ============================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置变量
APP_NAME="yunyutong"
APP_USER="${SUDO_USER:-$(whoami)}"
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${APP_DIR}/venv"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
ENV_FILE="${APP_DIR}/.env"
LOG_DIR="${APP_DIR}/logs"
APP_PORT="8000"  # 应用监听端口

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 sudo 运行此脚本"
        echo "  用法: sudo bash $0"
        exit 1
    fi
}

# 检查操作系统
check_os() {
    if [ -f /etc/debian_version ]; then
        print_success "检测到 Debian/Ubuntu 系统"
    else
        print_warning "此脚本针对 Debian/Ubuntu 优化，其他系统可能需要手动调整"
        read -p "是否继续? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 安装系统依赖
install_dependencies() {
    print_header "安装系统依赖"
    
    print_info "更新软件包列表..."
    apt-get update -qq
    
    print_info "安装 Python3 和相关工具..."
    apt-get install -y -qq python3 python3-pip python3-venv python3-dev
    
    print_info "安装编译工具 (用于某些 Python 包)..."
    apt-get install -y -qq build-essential libffi-dev libssl-dev
    
    print_success "系统依赖安装完成"
}

# 创建虚拟环境
setup_venv() {
    print_header "配置 Python 虚拟环境"
    
    if [ -d "$VENV_DIR" ]; then
        print_warning "虚拟环境已存在: $VENV_DIR"
        read -p "是否删除并重新创建? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_DIR"
        else
            print_info "使用现有虚拟环境"
            return
        fi
    fi
    
    print_info "创建虚拟环境..."
    python3 -m venv "$VENV_DIR"
    
    print_info "升级 pip..."
    "$VENV_DIR/bin/pip3" install --upgrade pip -q
    
    print_success "虚拟环境创建完成: $VENV_DIR"
}

# 安装 Python 依赖
install_python_deps() {
    print_header "安装 Python 依赖"
    
    print_info "安装 requirements.txt 中的依赖..."
    "$VENV_DIR/bin/pip3" install -r "$APP_DIR/requirements.txt" -q
    
    print_info "安装 Gunicorn (生产 WSGI 服务器)..."
    "$VENV_DIR/bin/pip3" install gunicorn -q
    
    print_success "Python 依赖安装完成"
}

# 生成密钥
generate_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}

generate_fernet_key() {
    "$VENV_DIR/bin/python3" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
}

# 配置环境变量
setup_env() {
    print_header "配置环境变量"
    
    if [ -f "$ENV_FILE" ]; then
        print_warning ".env 文件已存在"
        read -p "是否覆盖? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "保留现有 .env 文件"
            return
        fi
        cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "已备份原 .env 文件"
    fi
    
    print_info "生成安全密钥..."
    SECRET_KEY=$(generate_key)
    ENCRYPTION_KEY=$(generate_fernet_key)
    
    cat > "$ENV_FILE" << EOF
# 云域通 (YunYuTong) 环境配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

# Flask 配置
FLASK_APP=run.py
FLASK_ENV=production
FLASK_DEBUG=0

# 安全密钥 (请勿泄露!)
SECRET_KEY='${SECRET_KEY}'

# API Token 加密密钥 (Fernet, 请勿泄露!)
ENCRYPTION_KEY='${ENCRYPTION_KEY}'

# 数据库配置 (默认使用 SQLite)
# DATABASE_URL=sqlite:///${APP_DIR}/yunyutong.db

# 可选: 使用 PostgreSQL
# DATABASE_URL=postgresql://user:password@localhost/yunyutong

# 可选: 使用 MySQL
# DATABASE_URL=mysql+pymysql://user:password@localhost/yunyutong
EOF

    chmod 600 "$ENV_FILE"
    chown "$APP_USER:$APP_USER" "$ENV_FILE"
    
    print_success ".env 文件已创建"
    print_warning "请妥善保管 SECRET_KEY 和 ENCRYPTION_KEY!"
}

# 创建日志目录
setup_logs() {
    print_header "配置日志目录"
    
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
    fi
    
    chown -R "$APP_USER:$APP_USER" "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    
    print_success "日志目录已配置: $LOG_DIR"
}

# 初始化数据库
init_database() {
    print_header "初始化数据库"
    
    DB_FILE="${APP_DIR}/yunyutong.db"
    
    if [ -f "$DB_FILE" ]; then
        print_warning "数据库文件已存在: $DB_FILE"
        print_info "跳过数据库初始化"
    else
        print_info "创建数据库..."
        cd "$APP_DIR"
        
        # 以目标用户身份运行，避免权限问题
        if [ "$EUID" -eq 0 ] && [ -n "$APP_USER" ] && [ "$APP_USER" != "root" ]; then
            sudo -u "$APP_USER" "$VENV_DIR/bin/python3" << 'PYEOF'
from app import create_app
from app.extensions import db

app = create_app()
with app.app_context():
    db.create_all()
    print("数据库表已创建")
PYEOF
        else
            "$VENV_DIR/bin/python3" << 'PYEOF'
from app import create_app
from app.extensions import db

app = create_app()
with app.app_context():
    db.create_all()
    print("数据库表已创建")
PYEOF
        fi
        
        if [ $? -ne 0 ]; then
            print_error "数据库初始化失败"
            exit 1
        fi
    fi
    
    # 确保数据库文件权限正确
    if [ -f "$DB_FILE" ]; then
        chown "$APP_USER:$APP_USER" "$DB_FILE" 2>/dev/null || true
        chmod 644 "$DB_FILE" 2>/dev/null || true
    fi
    
    print_success "数据库配置完成"
}

# 设置目录权限
setup_permissions() {
    print_header "设置目录权限"
    
    print_info "设置应用目录所有者..."
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    
    print_info "设置目录权限..."
    # 设置目录权限为 755
    find "$APP_DIR" -type d -exec chmod 755 {} \;
    
    # 设置普通文件权限为 644，但排除 venv/bin 目录
    find "$APP_DIR" -type f ! -path "*/venv/bin/*" -exec chmod 644 {} \;
    
    # venv/bin 下的文件需要执行权限
    if [ -d "$VENV_DIR/bin" ]; then
        print_info "设置虚拟环境可执行文件权限..."
        chmod 755 "$VENV_DIR/bin/"* 2>/dev/null || true
    fi
    
    # 脚本文件需要执行权限
    chmod +x "$APP_DIR/deploy.sh" 2>/dev/null || true
    chmod +x "$APP_DIR/run.py" 2>/dev/null || true
    
    # 敏感文件
    chmod 600 "$ENV_FILE" 2>/dev/null || true
    
    print_success "权限设置完成"
}

# 创建 systemd 服务
setup_systemd() {
    print_header "配置 Systemd 服务"
    
    # 获取 CPU 核心数计算 workers
    CPU_CORES=$(nproc)
    WORKERS=$((CPU_CORES * 2 + 1))
    if [ $WORKERS -gt 9 ]; then
        WORKERS=9
    fi
    
    print_info "创建服务文件: $SERVICE_FILE"
    print_info "Gunicorn workers: $WORKERS (基于 $CPU_CORES 核心)"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=YunYuTong DNS Management System
Documentation=https://github.com/Anikato/yunyutong
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}

# 环境变量
Environment="PATH=${VENV_DIR}/bin"
EnvironmentFile=${ENV_FILE}

# Gunicorn 启动命令 (绑定到本地端口)
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --workers ${WORKERS} \\
    --worker-class sync \\
    --bind 127.0.0.1:${APP_PORT} \\
    --access-logfile ${LOG_DIR}/access.log \\
    --error-logfile ${LOG_DIR}/error.log \\
    --capture-output \\
    --timeout 120 \\
    --graceful-timeout 30 \\
    run:app

# 重启策略
Restart=always
RestartSec=5

# 安全限制
NoNewPrivileges=true
PrivateTmp=true

# 资源限制
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    print_info "重新加载 systemd 配置..."
    systemctl daemon-reload
    
    print_info "启用开机自启..."
    systemctl enable "$APP_NAME"
    
    print_success "Systemd 服务配置完成"
}

# 启动服务
start_service() {
    print_header "启动服务"
    
    print_info "启动 $APP_NAME 服务..."
    systemctl start "$APP_NAME"
    
    sleep 2
    
    if systemctl is-active --quiet "$APP_NAME"; then
        print_success "服务启动成功!"
        echo ""
        systemctl status "$APP_NAME" --no-pager
    else
        print_error "服务启动失败，请检查日志:"
        echo "  journalctl -u $APP_NAME -n 50"
        exit 1
    fi
}

# 显示部署信息
show_info() {
    print_header "部署完成"
    
    echo -e "${GREEN}云域通部署成功!${NC}"
    echo ""
    echo "========== 重要信息 =========="
    echo ""
    echo -e "应用目录:    ${CYAN}${APP_DIR}${NC}"
    echo -e "虚拟环境:    ${CYAN}${VENV_DIR}${NC}"
    echo -e "配置文件:    ${CYAN}${ENV_FILE}${NC}"
    echo -e "日志目录:    ${CYAN}${LOG_DIR}${NC}"
    echo -e "监听地址:    ${CYAN}127.0.0.1:${APP_PORT}${NC}"
    echo ""
    echo "========== 常用命令 =========="
    echo ""
    echo "查看服务状态:  sudo systemctl status $APP_NAME"
    echo "启动服务:      sudo systemctl start $APP_NAME"
    echo "停止服务:      sudo systemctl stop $APP_NAME"
    echo "重启服务:      sudo systemctl restart $APP_NAME"
    echo "查看日志:      sudo journalctl -u $APP_NAME -f"
    echo "查看访问日志:  tail -f ${LOG_DIR}/access.log"
    echo "查看错误日志:  tail -f ${LOG_DIR}/error.log"
    echo ""
    echo "========== 下一步 =========="
    echo ""
    echo "1. 配置 Nginx 反向代理 (参考 nginx.conf.example)"
    echo "2. 配置 HTTPS 证书 (推荐使用 Certbot)"
    echo "3. 访问应用注册管理员账号"
    echo ""
    print_warning "首次使用请配置 Nginx 后访问 http://your-domain/ 注册账号"
}

# 仅安装依赖模式 (用于开发环境)
install_only() {
    print_header "仅安装依赖模式 (开发环境)"
    setup_venv
    install_python_deps
    setup_env
    setup_logs
    init_database
    print_success "依赖安装完成"
    echo ""
    echo "========== 开发环境就绪 =========="
    echo ""
    echo "激活虚拟环境: source ${VENV_DIR}/bin/activate"
    echo "运行开发服务器: flask run --debug"
    echo ""
    echo "或者直接运行: ${VENV_DIR}/bin/flask run --debug"
}

# 显示帮助
show_help() {
    echo "云域通 (YunYuTong) 部署脚本"
    echo ""
    echo "用法: sudo bash $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --help, -h       显示此帮助信息"
    echo "  --install-only   仅安装依赖 (用于开发环境)"
    echo "  --update         更新依赖并重启服务"
    echo "  --restart        重启服务"
    echo "  --status         查看服务状态"
    echo "  --uninstall      卸载服务 (保留数据)"
    echo ""
    echo "无参数运行将执行完整生产部署"
}

# 重启服务
restart_service() {
    print_header "重启服务"
    
    if ! systemctl is-enabled --quiet "$APP_NAME" 2>/dev/null; then
        print_error "服务未安装或未启用"
        exit 1
    fi
    
    print_info "重启 $APP_NAME 服务..."
    systemctl restart "$APP_NAME"
    
    sleep 2
    
    if systemctl is-active --quiet "$APP_NAME"; then
        print_success "服务重启成功"
        systemctl status "$APP_NAME" --no-pager
    else
        print_error "服务重启失败"
        journalctl -u "$APP_NAME" -n 20 --no-pager
        exit 1
    fi
}

# 查看服务状态
show_status() {
    print_header "服务状态"
    
    if ! systemctl is-enabled --quiet "$APP_NAME" 2>/dev/null; then
        print_warning "服务未安装"
        exit 0
    fi
    
    systemctl status "$APP_NAME" --no-pager
    echo ""
    print_info "最近日志:"
    journalctl -u "$APP_NAME" -n 10 --no-pager
}

# 更新模式
update() {
    print_header "更新应用"
    
    # 检查虚拟环境是否存在
    if [ ! -d "$VENV_DIR" ]; then
        print_error "虚拟环境不存在: $VENV_DIR"
        print_info "请先运行完整部署: sudo bash $0"
        exit 1
    fi
    
    # 检查服务是否存在
    if [ ! -f "$SERVICE_FILE" ]; then
        print_error "服务文件不存在: $SERVICE_FILE"
        print_info "请先运行完整部署: sudo bash $0"
        exit 1
    fi
    
    print_info "更新 Python 依赖..."
    "$VENV_DIR/bin/pip3" install -r "$APP_DIR/requirements.txt" -q --upgrade
    
    print_info "重启服务..."
    systemctl restart "$APP_NAME"
    
    sleep 2
    
    if systemctl is-active --quiet "$APP_NAME"; then
        print_success "更新完成，服务已重启"
    else
        print_error "服务重启失败，请检查日志:"
        echo "  journalctl -u $APP_NAME -n 50"
        exit 1
    fi
}

# 卸载服务
uninstall() {
    print_header "卸载服务"
    
    print_warning "这将停止并移除 systemd 服务 (数据将保留)"
    read -p "确定要继续吗? [y/N] " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    print_info "停止服务..."
    systemctl stop "$APP_NAME" 2>/dev/null || true
    
    print_info "禁用开机自启..."
    systemctl disable "$APP_NAME" 2>/dev/null || true
    
    print_info "删除服务文件..."
    rm -f "$SERVICE_FILE"
    
    print_info "重新加载 systemd..."
    systemctl daemon-reload
    
    print_success "服务已卸载"
    echo ""
    echo "数据文件保留在: $APP_DIR"
    echo "如需完全删除，请手动执行: rm -rf $APP_DIR"
}

# 主函数
main() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --install-only)
            install_only
            exit 0
            ;;
        --update)
            check_root
            update
            exit 0
            ;;
        --restart)
            check_root
            restart_service
            exit 0
            ;;
        --status)
            show_status
            exit 0
            ;;
        --uninstall)
            check_root
            uninstall
            exit 0
            ;;
    esac
    
    # 完整部署流程
    check_root
    check_os
    
    print_header "云域通 (YunYuTong) 一键部署"
    echo "应用目录: $APP_DIR"
    echo "运行用户: $APP_USER"
    echo ""
    read -p "是否开始部署? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        exit 0
    fi
    
    install_dependencies
    setup_venv
    install_python_deps
    setup_env
    setup_logs
    init_database
    setup_permissions
    setup_systemd
    start_service
    show_info
}

# 运行主函数
main "$@"
