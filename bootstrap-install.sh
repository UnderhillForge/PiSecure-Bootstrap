#!/bin/bash

# PiSecure Bootstrap Node Installation Script
# For Raspberry Pi 5 running 64-bit Raspberry Pi OS Lite
# Run with: curl -fsSL https://raw.githubusercontent.com/UnderhillForge/PiSecure-Bootstrap/main/install.sh | bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Raspberry Pi 5
check_hardware() {
    log_info "Checking hardware compatibility..."

    if ! grep -q "Raspberry Pi 5" /proc/device-tree/model 2>/dev/null; then
        log_warning "This script is optimized for Raspberry Pi 5. Continuing anyway..."
    fi

    # Check if 64-bit
    if ! uname -m | grep -q "aarch64"; then
        log_error "This script requires 64-bit Raspberry Pi OS"
        exit 1
    fi

    log_success "Hardware check passed"
}

# Update system
update_system() {
    log_info "Updating system packages..."
    apt update && apt upgrade -y
    log_success "System updated"
}

# Install required packages
install_dependencies() {
    log_info "Installing required packages..."

    # Core system packages
    apt install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        htop \
        iotop \
        nmon \
        sqlite3 \
        libsqlite3-dev \
        ufw \
        fail2ban \
        unattended-upgrades \
        apt-listchanges \
        rsyslog \
        logrotate \
        cron \
        vim \
        nano \
        screen \
        tmux \
        jq \
        bc \
        lsof \
        net-tools \
        iputils-ping \
        dnsutils \
        traceroute \
        nmap \
        tcpdump \
        iptables \
        nftables

    # Python scientific computing packages
    pip3 install --upgrade pip setuptools wheel
    pip3 install \
        numpy \
        scipy \
        scikit-learn \
        pandas \
        flask \
        flask-cors \
        sqlalchemy \
        requests \
        ipaddress \
        statistics \
        sklearn \
        joblib

    log_success "Dependencies installed"
}

# Setup firewall
setup_firewall() {
    log_info "Configuring firewall..."

    # Enable UFW
    ufw --force enable

    # Allow SSH (for management)
    ufw allow ssh

    # Allow PiSecure bootstrap ports
    ufw allow 3142/tcp  # PiSecure bootstrap port
    ufw allow 8080/tcp  # HTTP API port

    # Rate limiting for API endpoints
    ufw limit 3142/tcp
    ufw limit 8080/tcp

    log_success "Firewall configured"
}

# Setup automatic security updates
setup_security_updates() {
    log_info "Configuring automatic security updates..."

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    # Enable unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades

    log_success "Automatic security updates configured"
}

# Setup fail2ban for SSH protection
setup_fail2ban() {
    log_info "Configuring fail2ban for SSH protection..."

    # Enable fail2ban service
    systemctl enable fail2ban
    systemctl start fail2ban

    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    systemctl restart fail2ban

    log_success "Fail2ban configured for SSH protection"
}

# Clone and setup PiSecure bootstrap
setup_pisecure() {
    log_info "Setting up PiSecure Bootstrap Node..."

    # Create pisecure user
    if ! id -u pisecure > /dev/null 2>&1; then
        useradd -r -s /bin/false pisecure
        log_info "Created pisecure system user"
    fi

    # Create application directory
    mkdir -p /opt/pisecure
    chown pisecure:pisecure /opt/pisecure

    # Clone repository
    if [ ! -d "/opt/pisecure/bootstrap" ]; then
        cd /opt/pisecure
        git clone https://github.com/UnderhillForge/PiSecure-Bootstrap.git bootstrap
        chown -R pisecure:pisecure /opt/pisecure/bootstrap
    fi

    # Create Python virtual environment
    cd /opt/pisecure/bootstrap
    python3 -m venv venv
    chown -R pisecure:pisecure /opt/pisecure/bootstrap

    # Activate venv and install requirements
    su -s /bin/bash pisecure -c "
        cd /opt/pisecure/bootstrap
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        pip install numpy scipy scikit-learn pandas flask flask-cors sqlalchemy requests
    "

    # Create logs directory
    mkdir -p /var/log/pisecure
    chown pisecure:pisecure /var/log/pisecure

    # Create data directory for SQLite database
    mkdir -p /var/lib/pisecure
    chown pisecure:pisecure /var/lib/pisecure

    log_success "PiSecure Bootstrap Node setup complete"
}

# Create systemd service
create_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/pisecure-bootstrap.service << EOF
[Unit]
Description=PiSecure Bootstrap Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=pisecure
Group=pisecure
WorkingDirectory=/opt/pisecure/bootstrap
Environment=PATH=/opt/pisecure/bootstrap/venv/bin
ExecStart=/opt/pisecure/bootstrap/venv/bin/python3 /opt/pisecure/bootstrap/bootstrap/server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pisecure-bootstrap

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/pisecure /var/lib/pisecure /opt/pisecure/bootstrap
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes

# Resource limits
LimitNOFILE=65536
MemoryLimit=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable pisecure-bootstrap

    log_success "Systemd service created and enabled"
}

# Setup logrotate for PiSecure logs
setup_logging() {
    log_info "Configuring log rotation..."

    cat > /etc/logrotate.d/pisecure << EOF
/var/log/pisecure/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0644 pisecure pisecure
    postrotate
        systemctl reload pisecure-bootstrap
    endscript
}
EOF

    log_success "Log rotation configured"
}

# Setup monitoring and alerts
setup_monitoring() {
    log_info "Setting up monitoring and health checks..."

    # Create health check script
    cat > /usr/local/bin/pisecure-health-check << 'EOF'
#!/bin/bash
# PiSecure Bootstrap Health Check Script

HEALTH_CHECK_URL="http://localhost:8080/health"
LOG_FILE="/var/log/pisecure/health-check.log"

# Check if service is running
if ! systemctl is-active --quiet pisecure-bootstrap; then
    echo "$(date): PiSecure service is not running" >> "$LOG_FILE"
    systemctl start pisecure-bootstrap
    exit 1
fi

# Check HTTP health endpoint
if ! curl -f -s --max-time 10 "$HEALTH_CHECK_URL" > /dev/null; then
    echo "$(date): Health check failed - restarting service" >> "$LOG_FILE"
    systemctl restart pisecure-bootstrap
    exit 1
fi

echo "$(date): Health check passed" >> "$LOG_FILE"
EOF

    chmod +x /usr/local/bin/pisecure-health-check

    # Add health check to cron (every 5 minutes)
    cat > /etc/cron.d/pisecure-health-check << EOF
*/5 * * * * root /usr/local/bin/pisecure-health-check
EOF

    log_success "Health monitoring configured"
}

# Setup backup system
setup_backup() {
    log_info "Setting up backup system..."

    # Create backup script
    cat > /usr/local/bin/pisecure-backup << 'EOF'
#!/bin/bash
# PiSecure Bootstrap Backup Script

BACKUP_DIR="/var/backups/pisecure"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/pisecure_backup_$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_FILE" \
    --exclude='*.log' \
    --exclude='__pycache__' \
    --exclude='venv' \
    /opt/pisecure \
    /var/lib/pisecure \
    /etc/systemd/system/pisecure-bootstrap.service

# Keep only last 7 backups
cd "$BACKUP_DIR"
ls -t *.tar.gz | tail -n +8 | xargs -r rm

echo "$(date): Backup completed - $BACKUP_FILE"
EOF

    chmod +x /usr/local/bin/pisecure-backup

    # Add daily backup to cron
    cat > /etc/cron.d/pisecure-backup << EOF
0 2 * * * root /usr/local/bin/pisecure-backup
EOF

    # Run initial backup
    /usr/local/bin/pisecure-backup

    log_success "Backup system configured"
}

# Configure performance optimizations for RPi 5
optimize_performance() {
    log_info "Optimizing performance for Raspberry Pi 5..."

    # Enable zram for swap compression
    apt install -y zram-tools
    cat > /etc/default/zramswap << EOF
ALGO=lz4
PERCENT=50
EOF
    systemctl enable zramswap
    systemctl start zramswap

    # Optimize kernel parameters
    cat >> /etc/sysctl.conf << EOF

# PiSecure Bootstrap Optimizations
net.core.somaxconn=1024
net.core.netdev_max_backlog=5000
net.ipv4.tcp_max_syn_backlog=1024
net.ipv4.ip_local_port_range=1024 65535

# Memory management
vm.swappiness=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5

# File system optimizations
fs.file-max=100000
EOF

    sysctl -p

    # Optimize Python performance
    cat >> /etc/environment << EOF
PYTHONOPTIMIZE=1
PYTHONDONTWRITEBYTECODE=1
EOF

    log_success "Performance optimizations applied"
}

# Setup SSH hardening
harden_ssh() {
    log_info "Hardening SSH configuration..."

    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Apply hardening
    cat >> /etc/ssh/sshd_config << EOF

# PiSecure SSH Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 60
ClientAliveCountMax 3
MaxAuthTries 3
LoginGraceTime 20
EOF

    # Restart SSH
    systemctl restart ssh

    log_success "SSH hardened"
}

# Final setup and startup
finalize_setup() {
    log_info "Finalizing PiSecure Bootstrap Node setup..."

    # Set proper permissions
    chown -R pisecure:pisecure /opt/pisecure
    chown -R pisecure:pisecure /var/log/pisecure
    chown -R pisecure:pisecure /var/lib/pisecure

    # Create environment configuration
    cat > /opt/pisecure/bootstrap/.env << EOF
# PiSecure Bootstrap Configuration
FLASK_ENV=production
PORT=8080
BOOTSTRAP_OPERATOR_WALLET=
BOOTSTRAP_REWARD_PERCENTAGE=0.05
BOOTSTRAP_MINIMUM_PAYOUT=10
BOOTSTRAP_DAILY_BUDGET=1000

# Database
DATABASE_URL=sqlite:////var/lib/pisecure/pisecure_bootstrap.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/pisecure/bootstrap.log

# Network
BOOTSTRAP_HOST=0.0.0.0
BOOTSTRAP_PORT=3142
API_HOST=0.0.0.0
API_PORT=8080
EOF

    chown pisecure:pisecure /opt/pisecure/bootstrap/.env

    # Start the service
    log_info "Starting PiSecure Bootstrap Node service..."
    systemctl start pisecure-bootstrap

    # Wait a moment for startup
    sleep 5

    # Check if service started successfully
    if systemctl is-active --quiet pisecure-bootstrap; then
        log_success "PiSecure Bootstrap Node started successfully!"
        log_info "Service Status: $(systemctl status pisecure-bootstrap --no-pager -l | grep Active)"
    else
        log_error "Failed to start PiSecure Bootstrap Node"
        log_info "Check logs: journalctl -u pisecure-bootstrap -f"
        exit 1
    fi
}

# Print completion message
print_completion() {
    log_success "PiSecure Bootstrap Node installation completed!"
    echo
    echo "=================================================================="
    echo "🎉 PiSecure Bootstrap Node Setup Complete!"
    echo "=================================================================="
    echo
    echo "📊 Service Information:"
    echo "   • Main Service: http://$(hostname -I | awk '{print $1}'):3142"
    echo "   • API/Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
    echo "   • Status: $(systemctl is-active pisecure-bootstrap)"
    echo
    echo "🔧 Management Commands:"
    echo "   • Check status: sudo systemctl status pisecure-bootstrap"
    echo "   • View logs: sudo journalctl -u pisecure-bootstrap -f"
    echo "   • Restart: sudo systemctl restart pisecure-bootstrap"
    echo "   • Stop: sudo systemctl stop pisecure-bootstrap"
    echo
    echo "📁 Important Directories:"
    echo "   • Application: /opt/pisecure/bootstrap"
    echo "   • Logs: /var/log/pisecure"
    echo "   • Data: /var/lib/pisecure"
    echo "   • Backups: /var/backups/pisecure"
    echo
    echo "🔒 Security Features:"
    echo "   • UFW Firewall configured"
    echo "   • Fail2ban SSH protection"
    echo "   • Automatic security updates"
    echo "   • SSH hardening applied"
    echo
    echo "📈 Monitoring:"
    echo "   • Health checks every 5 minutes"
    echo "   • Daily backups at 2 AM"
    echo "   • Log rotation configured"
    echo "   • Resource monitoring active"
    echo
    echo "🚀 Next Steps:"
    echo "   1. Configure your operator wallet in /opt/pisecure/bootstrap/.env"
    echo "   2. Access the dashboard at http://$(hostname -I | awk '{print $1}'):8080/nodes"
    echo "   3. Monitor logs and performance"
    echo "   4. Join the PiSecure network federation"
    echo
    echo "=================================================================="
    echo "🎯 PiSecure Bootstrap Node is now running on your Raspberry Pi 5!"
    echo "=================================================================="
}

# Main installation function
main() {
    echo "=================================================================="
    echo "🚀 PiSecure Bootstrap Node Installation for Raspberry Pi 5"
    echo "=================================================================="
    echo

    # Run installation steps
    check_hardware
    update_system
    install_dependencies
    setup_firewall
    setup_security_updates
    setup_fail2ban
    setup_pisecure
    create_service
    setup_logging
    setup_monitoring
    setup_backup
    optimize_performance
    harden_ssh
    finalize_setup

    # Print completion message
    print_completion
}

# Run main installation
main "$@"