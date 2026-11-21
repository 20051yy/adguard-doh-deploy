#!/usr/bin/env bash
#
# AdGuard Home + 加密 DNS 一键部署脚本
#
# 用途：在一台全新的 Ubuntu 22.04 / 24.04 VPS 上，一键部署 AdGuard Home，
# 并按选择的模式提供明文或加密 DNS（DoH / DoT / DoQ）。
#
# 四种模式（运行后按菜单选择）：
#   1 明文             ：只装 AdGuard Home，DNS 走 UDP/TCP 53，无加密。
#   2 加密直连 DoH     ：AdGuard + acme.sh（Cloudflare DNS 验证）签证书
#                        + nginx 反代 DoH，可选 sing-box VLESS+REALITY（443 端口）。
#   3 加密经 Cloudflare Tunnel：
#                        AdGuard + cloudflared 隧道，DoH 经隧道对外，
#                        不需要源站证书、不需要 nginx、不暴露服务器 IP。
#   4 零依赖加密       ：只需要一台 VPS。公网 IP 生成 sslip.io 域名，
#                        Let's Encrypt HTTP-01 签证书 + nginx 反代 DoH；
#                        直连走不通（80/443 被拦）时自动切 trycloudflare
#                        快速隧道兜底。不需要域名、Cloudflare 账号、API Token、浏览器登录。
#
# 用法：
#   curl -fsSL <raw-url>/install.sh | sudo bash
#   或下载后：sudo bash install.sh
#
# 要求：Ubuntu 22.04 / 24.04，以 root 运行；模式 2 和 3 需要一个托管在
# Cloudflare 的域名；模式 2 还需要一个有 DNS:Edit 权限的 Cloudflare API Token；
# 模式 4 只需要一台有公网 IP 的 VPS，不需要域名和 Cloudflare 账号。
#
# 注意：本脚本不包含任何真实域名、IP、Token、密码或 UUID，
# 所有参数都在安装时由你输入；生成的密钥只写进本地凭据文件，不会上传到任何地方。
#
set -euo pipefail

export HOME=/root

# ---------------------------------------------------------------- 颜色输出
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

info() { echo -e "${BLUE}[信息]${NC} $*"; }
ok()   { echo -e "${GREEN}[完成]${NC} $*"; }
warn() { echo -e "${YELLOW}[注意]${NC} $*" >&2; }
err()  { echo -e "${RED}[错误]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------- 全局变量
AGH_DIR="/opt/AdGuardHome"
AGH_BIN="${AGH_DIR}/AdGuardHome"
AGH_CONF="${AGH_DIR}/AdGuardHome.yaml"
AGH_SERVICE="AdGuardHome"
CRED_FILE="/root/adguard-doh-credentials"
# example.com A 查询的固定测试向量（不是密钥，只是一条现成的 DNS 查询报文）
DOH_QUERY_B64="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

MODE=""
MODE_TEXT=""
MODE4_PATH=""
TLS_ENABLED="false"
TLS_SERVER_NAME=""
TLS_CERT=""
TLS_KEY=""
DOT_PORT="6789"
DOQ_PORT="6789"
SINGBOX_INSTALLED="n"
TUNNEL_ID=""

# ---------------------------------------------------------------- 基础检查
check_root() {
    [[ "$(id -u)" -eq 0 ]] || die "请以 root 运行本脚本（sudo bash install.sh）。"
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
    else
        die "无法识别系统：缺少 /etc/os-release，本脚本只支持 Ubuntu 22.04 / 24.04。"
    fi
    if [[ "${ID:-}" != "ubuntu" ]]; then
        die "不支持的系统：${PRETTY_NAME:-未知}。本脚本只支持 Ubuntu 22.04 / 24.04。"
    fi
    case "${VERSION_ID:-}" in
        22.04|24.04) ok "系统：${PRETTY_NAME}，符合要求。" ;;
        *) warn "系统是 ${PRETTY_NAME}，未在 Ubuntu 22.04 / 24.04 上验证过，继续安装可能失败。" ;;
    esac
}

apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || die "apt-get update 失败，请检查 VPS 网络与软件源。"
    apt-get install -y -qq "$@" || die "安装依赖失败：$*"
}

server_ip() {
    hostname -I 2>/dev/null | awk '{print $1}'
}

is_private_ip() {
    # 私网 / 回环 / 链路本地地址不能用来生成 sslip.io 域名
    [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.|0\.) ]]
}

public_ip() {
    # 返回本机公网 IPv4，失败返回 1。先问外网 IP 查询服务（多个备用），
    # 再兜底看本机网卡 IP（只有它是公网 IP 时才采用）。
    local ip="" svc=""
    for svc in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
        ip="$(curl -fsSL --noproxy '*' --max-time 10 "$svc" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ip "$ip"; then
            printf '%s' "$ip"
            return 0
        fi
    done
    ip="$(server_ip)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! is_private_ip "$ip"; then
        printf '%s' "$ip"
        return 0
    fi
    return 1
}

wait_for_http() {
    # wait_for_http <url> <超时秒数>：200 或 302 即视为就绪
    local url="$1" timeout="${2:-60}" i=0 code=""
    while (( i < timeout )); do
        # --noproxy '*'：检查的是本机服务，必须直连，不能走环境里可能存在的代理。
        code="$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || echo 000)"
        if [[ "$code" == "200" || "$code" == "302" ]]; then
            return 0
        fi
        sleep 2
        i=$((i + 2))
    done
    return 1
}

# ---------------------------------------------------------------- 交互提问
# 以下 ask 系列函数都支持用环境变量预先传参（例如 AGH_MODE=1 AGH_ADMIN_PASS=xxx），
# 环境变量已设置时不再提问，方便无人值守或测试时使用。

ask() {
    # ask <变量名> <提示> <默认值>
    local var="$1" prompt="$2" def="${3:-}" val=""
    if [[ -n "${!var:-}" ]]; then return 0; fi
    if [[ -n "$def" ]]; then
        read -rp "$prompt [$def]: " val
        val="${val:-$def}"
    else
        read -rp "$prompt: " val
    fi
    printf -v "$var" '%s' "$val"
}

ask_secret() {
    # ask_secret <变量名> <提示>：不回显，输两遍确认
    local var="$1" prompt="$2" v1="" v2=""
    if [[ -n "${!var:-}" ]]; then return 0; fi
    while true; do
        read -rsp "$prompt: " v1; echo
        read -rsp "请再输一次确认: " v2; echo
        if [[ -n "$v1" && "$v1" == "$v2" ]]; then break; fi
        warn "两次输入不一致或为空，请重新输入。"
    done
    printf -v "$var" '%s' "$v1"
}

ask_secret_once() {
    # ask_secret_once <变量名> <提示>：不回显，只输一次（用于 Token）
    local var="$1" prompt="$2" v=""
    if [[ -n "${!var:-}" ]]; then return 0; fi
    read -rsp "$prompt: " v; echo
    [[ -n "$v" ]] || die "输入不能为空。"
    printf -v "$var" '%s' "$v"
}

ask_yes_no() {
    # ask_yes_no <变量名> <提示> <默认 y/n>：结果为 y 或 n
    local var="$1" prompt="$2" def="${3:-n}" ans=""
    if [[ -n "${!var:-}" ]]; then return 0; fi
    while true; do
        if [[ "$def" == "y" ]]; then
            read -rp "$prompt [Y/n]: " ans; ans="${ans:-y}"
        else
            read -rp "$prompt [y/N]: " ans; ans="${ans:-n}"
        fi
        case "$ans" in
            y|Y|yes|YES) printf -v "$var" 'y'; return 0 ;;
            n|N|no|NO)   printf -v "$var" 'n'; return 0 ;;
            *) warn "请输入 y 或 n。" ;;
        esac
    done
}

# ---------------------------------------------------------------- 模式选择
choose_mode() {
    if [[ -n "${AGH_MODE:-}" ]]; then
        case "$AGH_MODE" in
            1|2|3|4) MODE="$AGH_MODE"; return 0 ;;
            *) die "环境变量 AGH_MODE 只能是 1、2、3 或 4，当前是：$AGH_MODE" ;;
        esac
    fi
    echo
    echo "==================== 部署模式 ===================="
    echo "  1) 明文"
    echo "     只装 AdGuard Home，DNS 走 UDP/TCP 53，不加密。"
    echo "     适合：局域网 / 可信网络，或只想先跑起来试试。"
    echo
    echo "  2) 加密直连 DoH"
    echo "     AdGuard + acme.sh 证书（Cloudflare DNS 验证）+ nginx 反代 DoH，"
    echo "     可选 sing-box VLESS+REALITY（443 端口，回落到 nginx DoH）。"
    echo "     适合：有 Cloudflare 托管域名，想直接用 443 提供加密 DNS。"
    echo
    echo "  3) 加密经 Cloudflare Tunnel"
    echo "     AdGuard + cloudflared 隧道，DoH 经隧道对外，不暴露服务器 IP，"
    echo "     不需要源站证书、不需要 nginx。"
    echo "     适合：直连 443 被运营商干扰、或不想暴露服务器 IP 的情况。"
    echo
    echo "  4) 零依赖加密（直连优先，失败走快速隧道）"
    echo "     只需要一台 VPS：公网 IP 生成 sslip.io 域名，Let's Encrypt"
    echo "     HTTP-01 签证书 + nginx 反代 DoH；直连不通（80/443 被拦）时"
    echo "     自动切 trycloudflare 快速隧道兜底。"
    echo "     适合：没有域名、没有 Cloudflare 账号，只想一条命令装好加密 DNS。"
    echo "=================================================="
    local c=""
    while true; do
        read -rp "请输入 1/2/3/4: " c
        case "$c" in
            1|2|3|4) MODE="$c"; return 0 ;;
            *) warn "请输入 1、2、3 或 4。" ;;
        esac
    done
}

validate_doh_host() {
    if [[ "$AGH_DOH_HOST" =~ ^https?:// ]]; then
        die "DoH 域名请只填域名，不要带 https:// 前缀，例如：doh.example.com"
    fi
    if [[ ! "$AGH_DOH_HOST" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        die "DoH 域名格式不正确：$AGH_DOH_HOST"
    fi
}

prompt_common() {
    echo
    info "下面是通用设置（所有模式都要问）。"
    ask AGH_ADMIN_USER "AdGuard 管理员用户名" "admin"
    ask_secret AGH_ADMIN_PASS "AdGuard 管理员密码（输入不回显）"
    ask AGH_ADMIN_PORT "AdGuard 管理面板端口" "32450"
    if ! [[ "$AGH_ADMIN_PORT" =~ ^[0-9]+$ ]] || (( AGH_ADMIN_PORT < 1 || AGH_ADMIN_PORT > 65535 )); then
        die "管理面板端口必须是 1-65535 的数字：$AGH_ADMIN_PORT"
    fi
    if [[ "$AGH_ADMIN_PORT" == "53" || "$AGH_ADMIN_PORT" == "8090" || "$AGH_ADMIN_PORT" == "6789" || "$AGH_ADMIN_PORT" == "853" ]]; then
        die "管理面板端口不能是 53 / 8090 / 6789 / 853，这些端口要留给 DNS 用。"
    fi
    ask AGH_UPSTREAM "上游 DNS（逗号分隔，可回车用默认）" "https://dns10.quad9.net/dns-query,1.1.1.1"
}

prompt_mode2() {
    echo
    info "模式 2 需要一个托管在 Cloudflare 的域名，证书用 Cloudflare DNS 验证签发，"
    info "域名不需要提前把 A 记录指到这台 VPS，但部署完成后 DoH 要能用，"
    info "域名的 A 记录必须指向这台 VPS 的公网 IP。"
    ask AGH_DOH_HOST "DoH 域名（例如 doh.example.com）" ""
    [[ -n "${AGH_DOH_HOST:-}" ]] || die "DoH 域名不能为空。"
    validate_doh_host
    ask_secret_once AGH_CF_TOKEN "Cloudflare API Token（需要对应域名的 DNS:Edit 权限，输入不回显）"
    ask AGH_CF_EMAIL "Cloudflare 账号邮箱（用于 ZeroSSL 注册）" ""
    [[ -n "${AGH_CF_EMAIL:-}" ]] || die "Cloudflare 账号邮箱不能为空。"
    echo "证书颁发机构：1) ZeroSSL（默认，ECC 证书）  2) Let's Encrypt"
    ask AGH_CA "请选择 1 或 2" "1"
    case "$AGH_CA" in
        1|2) ;;
        *) die "AGH_CA 只能是 1 或 2。" ;;
    esac
    ask_yes_no AGH_INSTALL_SINGBOX "是否同时安装 sing-box VLESS+REALITY（占用 443 端口，非 REALITY 握手回落到 nginx DoH）" "n"
    if [[ "$AGH_INSTALL_SINGBOX" == "y" ]]; then
        ask AGH_REALITY_SNI "REALITY 伪装域名 SNI（建议用一个真实存在的大站域名）" "www.microsoft.com"
    fi
}

prompt_mode3() {
    echo
    info "模式 3 需要一个托管在 Cloudflare 的域名，DoH 域名会通过隧道对外，"
    info "不需要源站证书，也不需要把服务器 IP 暴露出去。"
    warn "注意：同一个域名不能同时有 A 记录和 CNAME 记录。"
    warn "如果这个 DoH 域名已经有 A 记录指到别处，请换一个没有被占用的子域名，"
    warn "例如主域名留给直连用，另起一个子域名走隧道。"
    ask AGH_TUNNEL_NAME "隧道名称（不能含空格）" "adguard-doh"
    if [[ "$AGH_TUNNEL_NAME" =~ [[:space:]] ]]; then
        die "隧道名称不能包含空格：$AGH_TUNNEL_NAME"
    fi
    ask AGH_DOH_HOST "DoH 域名（例如 doh.example.com）" ""
    [[ -n "${AGH_DOH_HOST:-}" ]] || die "DoH 域名不能为空。"
    validate_doh_host
}

prompt_mode4() {
    echo
    info "模式 4 不需要域名、Cloudflare 账号、API Token 或浏览器登录，"
    info "只需要这台 VPS：先尝试用 <公网IP>.sslip.io 直连签发 Let's Encrypt 证书，"
    info "直连走不通（80/443 被拦）时自动切到 trycloudflare 快速隧道兜底。"
    warn "快速隧道的域名每次重启服务会变，变了要更新客户端配置；"
    warn "想要固定域名请用模式 3（需要 Cloudflare 账号）。"
    # AGH_FORCE_TUNNEL=1（或 y）强制直接走隧道，跳过直连尝试；不设置则提问。
    ask_yes_no AGH_FORCE_TUNNEL "是否跳过直连，直接走快速隧道" "n"
    case "${AGH_FORCE_TUNNEL:-n}" in
        1|y|Y|yes|YES) AGH_FORCE_TUNNEL="y" ;;
        *) AGH_FORCE_TUNNEL="n" ;;
    esac
}

# ---------------------------------------------------------------- AdGuard Home
install_adguard() {
    info "安装依赖：curl ca-certificates gnupg socat apache2-utils dnsutils iproute2 cron ..."
    apt_install curl ca-certificates gnupg lsb-release socat apache2-utils dnsutils iproute2 cron

    if [[ ! -x "$AGH_BIN" ]]; then
        info "安装 AdGuard Home（官方安装脚本）..."
        curl -fsSL https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh \
            -o /tmp/agh-install.sh || die "下载 AdGuard Home 安装脚本失败，请检查网络。"
        sh /tmp/agh-install.sh -v || die "AdGuard Home 安装失败，请检查上面的输出。"
        rm -f /tmp/agh-install.sh
    else
        info "检测到已安装的 AdGuard Home，跳过安装。"
    fi
    [[ -x "$AGH_BIN" ]] || die "未找到 AdGuard Home 可执行文件：$AGH_BIN"
    ok "AdGuard Home 已安装：$("$AGH_BIN" --version 2>/dev/null | head -1 || echo 未知版本)"

    # 写配置前先停掉服务，避免它占用端口或覆盖配置文件
    if systemctl is-active --quiet "$AGH_SERVICE" 2>/dev/null; then
        info "停止正在运行的 AdGuard Home，准备写配置..."
        systemctl stop "$AGH_SERVICE" || true
    fi
}

gen_pass_hash() {
    # 用 htpasswd 生成 bcrypt 哈希（AdGuard Home 接受 $2y$ 格式）
    local hash=""
    hash="$(htpasswd -nbB "$AGH_ADMIN_USER" "$AGH_ADMIN_PASS" | cut -d: -f2-)"
    [[ -n "$hash" ]] || die "生成管理员密码哈希失败。"
    printf '%s' "$hash"
}

extract_existing_users() {
    # 如果已有配置且包含 users 段，原样保留：重跑脚本不会覆盖已有管理员账号
    if [[ -f "$AGH_CONF" ]] && grep -q '^users:' "$AGH_CONF"; then
        awk 'BEGIN{p=0} /^users:/{p=1} p==1 && /^[^[:space:]#]/ && !/^users:/{p=0} p==1{print}' "$AGH_CONF"
    fi
}

write_agh_config() {
    # 根据当前模式变量写 AdGuardHome.yaml：
    #   TLS_ENABLED / TLS_SERVER_NAME / TLS_CERT / TLS_KEY 由 main() 按模式设置。
    #   模式 1：TLS 关闭；模式 2：TLS 开 + acme.sh 证书路径（续期后 AdGuard 会自动重读，
    #   证书路径直接引用 acme.sh 的文件）；模式 3：TLS 开 + 不填证书路径，
    #   AdGuard 启动时自动生成自签名证书（隧道用 noTLSVerify 连接，不校验它）。
    #   模式 4 直连：同模式 2；模式 4 隧道兜底：同模式 3（自签名证书）。
    #   DOT_PORT / DOQ_PORT 默认 6789（模式 1/2/3），模式 4 用标准端口 853。
    local users_block=""
    if [[ -f "$AGH_CONF" ]]; then
        cp -a "$AGH_CONF" "${AGH_CONF}.bak.$(date +%Y%m%d%H%M%S)"
        info "已备份现有配置。"
        users_block="$(extract_existing_users || true)"
        # 提取到的块必须包含一行格式完整的密码行（缩进 + password: '<hash>' 且行尾无多余内容），
        # 否则当作没有（重新生成管理员账号）。旧版 bug 会把 dns: 粘在密码行尾，
        # 那种残缺的块不能复用。
        if [[ -n "$users_block" ]] && ! grep -qE "^[[:space:]]+password: '[^']*'$" <<< "$users_block"; then
            users_block=""
        fi
    fi
    if [[ -z "$users_block" ]]; then
        local hash=""
        hash="$(gen_pass_hash)"
        users_block=$(printf 'users:\n  - name: %s\n    password: %s\n' "$AGH_ADMIN_USER" "'$hash'")
    else
        info "检测到已有管理员账号，重跑脚本不会覆盖它（仍用原来的用户名和密码登录）。"
    fi

    local upstream_yaml="" u
    IFS=',' read -ra _ups <<< "$AGH_UPSTREAM"
    for u in "${_ups[@]}"; do
        upstream_yaml+="    - ${u}"$'\n'
    done

    cat > "$AGH_CONF" <<EOF
# AdGuard Home 配置（由一键部署脚本生成）
# schema_version 35 是 AdGuard Home v1.0.0 的当前版本；写上它可避免 AdGuard
# 把这份配置当成极旧版本做迁移（迁移会把 bootstrap_dns 错误地包成嵌套列表导致启动失败）。
# 新版 AdGuard 会在需要时自动向前迁移，无需手动改这里。
schema_version: 35
http:
  address: 0.0.0.0:${AGH_ADMIN_PORT}
  session_ttl: 720h
${users_block}
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  upstream_dns:
${upstream_yaml}  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  upstream_mode: load_balance
  cache_size: 4194304
  trusted_proxies:
    - 127.0.0.0/8
filtering:
  filtering_enabled: true
tls:
  enabled: ${TLS_ENABLED}
  server_name: ${TLS_SERVER_NAME}
  force_https: false
  port_https: 8090
  port_dns_over_tls: ${DOT_PORT}
  port_dns_over_quic: ${DOQ_PORT}
  certificate_path: ${TLS_CERT}
  private_key_path: ${TLS_KEY}
querylog:
  enabled: true
  interval: 2160h
statistics:
  enabled: true
  interval: 2160h
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
EOF
    ok "AdGuard 配置已写入：$AGH_CONF"
}

start_adguard() {
    systemctl enable "$AGH_SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$AGH_SERVICE" || die "AdGuard Home 启动失败，请查看：journalctl -u $AGH_SERVICE -n 100"
    info "等待 AdGuard Home 管理面板就绪（端口 ${AGH_ADMIN_PORT}）..."
    if ! wait_for_http "http://127.0.0.1:${AGH_ADMIN_PORT}/" 60; then
        die "AdGuard Home 管理面板在 60 秒内没有就绪，请查看：journalctl -u $AGH_SERVICE -n 100"
    fi
    ok "AdGuard Home 已运行，管理面板端口 ${AGH_ADMIN_PORT}。"

    info "验证明文 DNS（dig @127.0.0.1 example.com）..."
    local ans=""
    # 先试 UDP（主通道）；某些容器/沙箱会拦 UDP 回包，再试 TCP。
    # 只接受纯 IPv4 答案，dig 的报错文本（如 communications error）不算通过。
    ans="$(dig @127.0.0.1 example.com A +short +time=5 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)"
    if [[ -z "$ans" ]]; then
        ans="$(dig @127.0.0.1 example.com A +tcp +short +time=5 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)"
    fi
    if [[ -z "$ans" ]]; then
        die "AdGuard 明文 DNS 查询失败（dig @127.0.0.1 example.com 无返回）。可能原因：53 端口被别的服务占用，请检查 ss -tulpn | grep ':53'。"
    fi
    ok "明文 DNS 验证通过：example.com -> ${ans}"
}

# ---------------------------------------------------------------- 模式 2：证书 + nginx + sing-box
install_acme() {
    if [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then
        info "安装 acme.sh..."
        # 模式 2 有邮箱（ZeroSSL 注册用），模式 4 没有邮箱就不传（Let's Encrypt 不需要）。
        if [[ -n "${AGH_CF_EMAIL:-}" ]]; then
            curl -fsSL https://get.acme.sh | sh -s email="$AGH_CF_EMAIL" \
                || die "acme.sh 安装失败，请检查网络。"
        else
            curl -fsSL https://get.acme.sh | sh \
                || die "acme.sh 安装失败，请检查网络。"
        fi
    else
        info "检测到已安装的 acme.sh，跳过安装。"
    fi
    ACME="$HOME/.acme.sh/acme.sh"
    [[ -x "$ACME" ]] || die "未找到 acme.sh：$ACME"
}

issue_cert() {
    local ca_server=""
    if [[ "$AGH_CA" == "2" ]]; then
        ca_server="letsencrypt"
        info "证书颁发机构：Let's Encrypt"
    else
        ca_server="zerossl"
        info "证书颁发机构：ZeroSSL（ECC 证书）"
    fi
    "$ACME" --set-default-ca --server "$ca_server" \
        || die "设置默认 CA 失败。"

    info "签发证书（Cloudflare DNS 验证，域名：$AGH_DOH_HOST）..."
    export CF_Token="$AGH_CF_TOKEN"
    export CF_Email="$AGH_CF_EMAIL"
    if ! "$ACME" --issue --dns dns_cf -d "$AGH_DOH_HOST" --ecc; then
        unset CF_Token CF_Email
        die "证书签发失败：请检查 Cloudflare API Token 是否有该域名的 DNS:Edit 权限，以及域名是否已托管在该 Cloudflare 账号下。"
    fi
    unset CF_Token CF_Email

    mkdir -p "/etc/ssl/${AGH_DOH_HOST}"
    "$ACME" --install-cert -d "$AGH_DOH_HOST" --ecc \
        --cert-file "/etc/ssl/${AGH_DOH_HOST}/cert.cer" \
        --key-file "/etc/ssl/${AGH_DOH_HOST}/private.key" \
        --fullchain-file "/etc/ssl/${AGH_DOH_HOST}/fullchain.cer" \
        --reloadcmd "nginx -t && systemctl reload nginx; systemctl restart AdGuardHome" \
        || die "安装证书到 /etc/ssl/${AGH_DOH_HOST}/ 失败。"
    ok "证书已签发并安装到 /etc/ssl/${AGH_DOH_HOST}/，续期会自动重载 nginx 并重启 AdGuard。"
}

write_nginx_http01_vhost() {
    # 模式 4 专用：只监听 80，专门给 Let's Encrypt HTTP-01 验证用。
    # 用 webroot 方式签发（而不是 standalone），续期时 nginx 不用停，
    # 证书到期 acme.sh 能直接续上；签完证书后 write_nginx_vhost 再补 443 的 DoH 反代。
    apt_install nginx
    mkdir -p /var/www/html
    cat > /etc/nginx/conf.d/adguard-http01.conf <<EOF
# Let's Encrypt HTTP-01 验证（由一键部署脚本生成，模式 4）
server {
    listen 80;
    server_name ${AGH_DOH_HOST};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 404;
    }
}
EOF
    nginx -t || die "nginx 配置测试失败（nginx -t 未通过），请检查 /etc/nginx/conf.d/adguard-http01.conf。"
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx || systemctl restart nginx || die "nginx 重载失败。"
    ok "nginx HTTP-01 验证站点已生效（80 端口）。"
}

issue_cert_http01() {
    # 模式 4 专用：Let's Encrypt HTTP-01 签发 sslip.io 域名的真实证书。
    # 返回 0 = 签发成功；返回 1 = 失败（调用方自动切快速隧道兜底），不要直接 die。
    # CA 固定 Let's Encrypt，不用 ZeroSSL、不需要邮箱和 API Token。
    # 要求：域名能解析到本机、80 端口能从外网访问（Let's Encrypt 验证服务器要连进来）。
    "$ACME" --set-default-ca --server letsencrypt \
        || { warn "设置默认 CA（Let's Encrypt）失败。"; return 1; }

    info "签发证书（Let's Encrypt HTTP-01 验证，域名：$AGH_DOH_HOST，需 80 端口可达）..."
    if ! "$ACME" --issue --webroot /var/www/html -d "$AGH_DOH_HOST" --ecc; then
        warn "证书签发失败。常见原因：80 端口被运营商/防火墙拦截，或域名解析不到本机。"
        return 1
    fi

    mkdir -p "/etc/ssl/${AGH_DOH_HOST}"
    "$ACME" --install-cert -d "$AGH_DOH_HOST" --ecc \
        --cert-file "/etc/ssl/${AGH_DOH_HOST}/cert.cer" \
        --key-file "/etc/ssl/${AGH_DOH_HOST}/private.key" \
        --fullchain-file "/etc/ssl/${AGH_DOH_HOST}/fullchain.cer" \
        --reloadcmd "nginx -t && systemctl reload nginx; systemctl restart AdGuardHome" \
        || { warn "安装证书到 /etc/ssl/${AGH_DOH_HOST}/ 失败。"; return 1; }
    ok "证书已签发并安装到 /etc/ssl/${AGH_DOH_HOST}/，续期会自动重载 nginx 并重启 AdGuard。"
    return 0
}

write_nginx_vhost() {
    # write_nginx_vhost <listen 地址>
    #   有 sing-box 时传 127.0.0.1:8443（只监听本机，443 让给 sing-box 做 REALITY 回落）；
    #   没有 sing-box 时传 443（nginx 直接监听 443 提供 DoH）。
    local listen_addr="$1"
    apt_install nginx
    cat > /etc/nginx/conf.d/adguard-doh.conf <<EOF
# AdGuard Home DoH 反代（由一键部署脚本生成）
server {
    listen ${listen_addr} ssl http2;
    server_name ${AGH_DOH_HOST};

    ssl_certificate /etc/ssl/${AGH_DOH_HOST}/fullchain.cer;
    ssl_certificate_key /etc/ssl/${AGH_DOH_HOST}/private.key;

    location /dns-query {
        proxy_pass https://127.0.0.1:8090/dns-query;
        proxy_ssl_verify off;
        proxy_ssl_server_name on;
        proxy_ssl_name ${AGH_DOH_HOST};
        proxy_set_header Host ${AGH_DOH_HOST};
    }

    location / {
        return 404;
    }
}
EOF
    nginx -t || die "nginx 配置测试失败（nginx -t 未通过），请检查 /etc/nginx/conf.d/adguard-doh.conf。"
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx || systemctl restart nginx || die "nginx 重载失败（可能是 443 端口已被占用）。"
    ok "nginx DoH 反代已生效：https://${AGH_DOH_HOST}/dns-query"
}

install_singbox() {
    info "安装 sing-box（官方 apt 源）..."
    apt_install curl ca-certificates gnupg
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc \
        || die "下载 sing-box 签名密钥失败。"
    chmod a+r /etc/apt/keyrings/sagernet.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" \
        > /etc/apt/sources.list.d/sagernet.list
    apt-get update -qq || die "apt-get update 失败（sing-box 源）。"
    apt-get install -y -qq sing-box || die "安装 sing-box 失败。"
    command -v sing-box >/dev/null || die "sing-box 安装失败。"
    ok "sing-box 已安装：$(sing-box version 2>/dev/null | head -1)"
}

setup_singbox_reality() {
    local uuid="" kp="" priv="" pub="" short_id=""
    uuid="$(cat /proc/sys/kernel/random/uuid)"
    kp="$(sing-box generate reality-keypair)" || die "生成 REALITY 密钥失败。"
    priv="$(printf '%s' "$kp" | awk '/Private key:/{print $3}')"
    pub="$(printf '%s' "$kp" | awk '/Public key:/{print $3}')"
    [[ -n "$priv" && -n "$pub" ]] || die "解析 REALITY 密钥失败。"
    short_id="$(openssl rand -hex 4)"

    mkdir -p /etc/sing-box
    cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": 443,
      "users": [
        { "uuid": "${uuid}", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${AGH_REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "127.0.0.1", "server_port": 8443 },
          "private_key": "${priv}",
          "short_id": ["${short_id}"]
        }
      }
    }
  ]
}
EOF
    sing-box check -c /etc/sing-box/config.json || die "sing-box 配置校验失败。"
    systemctl enable sing-box >/dev/null 2>&1 || true
    systemctl restart sing-box || die "sing-box 启动失败，请查看：journalctl -u sing-box -n 100"
    systemctl is-active --quiet sing-box || die "sing-box 未正常运行。"

    local ip=""
    ip="$(server_ip)"
    {
        echo "# sing-box VLESS+REALITY（模式 2，生成时间：$(date -Is)）"
        echo "singbox_uuid=${uuid}"
        echo "reality_public_key=${pub}"
        echo "reality_private_key=${priv}"
        echo "reality_short_id=${short_id}"
        echo "reality_sni=${AGH_REALITY_SNI}"
        echo "vless_link=vless://${uuid}@${ip}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${AGH_REALITY_SNI}&fp=chrome&pbk=${pub}&sid=${short_id}&type=tcp#VLESS-REALITY"
    } >> "$CRED_FILE"
    chmod 600 "$CRED_FILE"
    ok "sing-box VLESS+REALITY 已运行（443 端口，非 REALITY 握手回落到 nginx DoH）。"
}

# ---------------------------------------------------------------- 模式 3：Cloudflare Tunnel
install_cloudflared() {
    if command -v cloudflared >/dev/null 2>&1; then
        info "检测到已安装的 cloudflared，跳过安装。"
        return 0
    fi
    info "安装 cloudflared（官方 .deb 包）..."
    local arch="" deb=""
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64) deb="cloudflared-linux-amd64.deb" ;;
        arm64) deb="cloudflared-linux-arm64.deb" ;;
        *) die "不支持的架构：$arch（仅支持 amd64 / arm64）。" ;;
    esac
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/${deb}" \
        -o "/tmp/${deb}" || die "下载 cloudflared 失败，请检查网络。"
    dpkg -i "/tmp/${deb}" || apt-get install -f -y -qq || die "安装 cloudflared 失败。"
    rm -f "/tmp/${deb}"
    command -v cloudflared >/dev/null || die "cloudflared 安装失败。"
    ok "cloudflared 已安装：$(cloudflared --version 2>/dev/null)"
}

write_tunnel_config() {
    # write_tunnel_config <隧道 ID>
    local tunnel_id="$1"
    mkdir -p "$HOME/.cloudflared"
    cat > "$HOME/.cloudflared/config.yml" <<EOF
# cloudflared 隧道配置（由一键部署脚本生成）
tunnel: ${tunnel_id}
credentials-file: ${HOME}/.cloudflared/${tunnel_id}.json
ingress:
  - hostname: ${AGH_DOH_HOST}
    service: https://127.0.0.1:8090
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
    grep -q "hostname: ${AGH_DOH_HOST}" "$HOME/.cloudflared/config.yml" \
        || die "隧道配置文件生成失败：$HOME/.cloudflared/config.yml"
    grep -q "noTLSVerify: true" "$HOME/.cloudflared/config.yml" \
        || die "隧道配置文件生成失败（缺少 noTLSVerify）。"
    ok "隧道配置文件已生成：$HOME/.cloudflared/config.yml"
}

setup_tunnel() {
    mkdir -p "$HOME/.cloudflared"
    if [[ ! -f "$HOME/.cloudflared/cert.pem" ]]; then
        echo
        echo "---- 需要你在浏览器里完成一次 Cloudflare 登录授权 ----"
        echo "下面会打印一个网址，请在你自己的电脑浏览器里打开它，"
        echo "登录 Cloudflare 并选择域名所在的账号，完成授权后回到这里按回车。"
        echo "------------------------------------------------------"
        cloudflared tunnel login || die "cloudflared 登录失败。"
        read -rp "已在浏览器中完成授权？按回车继续..." _dummy
    else
        info "检测到已有的 cloudflared 登录证书，跳过登录。"
    fi
    [[ -f "$HOME/.cloudflared/cert.pem" ]] \
        || die "未找到登录证书 $HOME/.cloudflared/cert.pem，请先完成 cloudflared tunnel login。"

    # 隧道名不能含空格（cloudflared tunnel list 按列解析会错位）
    if cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "$AGH_TUNNEL_NAME"; then
        info "隧道 ${AGH_TUNNEL_NAME} 已存在，直接复用。"
    else
        info "创建隧道 ${AGH_TUNNEL_NAME}..."
        local out=""
        out="$(cloudflared tunnel create "$AGH_TUNNEL_NAME" 2>&1)" \
            || die "创建隧道失败：$out"
        echo "$out"
    fi

    local tunnel_id=""
    tunnel_id="$(cloudflared tunnel list 2>/dev/null | awk -v n="$AGH_TUNNEL_NAME" '$2==n {print $1; exit}')"
    [[ -n "$tunnel_id" ]] || die "无法获取隧道 ID，请运行 cloudflared tunnel list 查看。"
    info "隧道 ID：$tunnel_id"

    # 先检查该域名是否已有 A 记录：同一域名不能同时有 A 记录和 CNAME，
    # tunnel route dns 需要创建 CNAME，有 A 记录会失败。
    local a_rec=""
    a_rec="$(dig +short "$AGH_DOH_HOST" A 2>/dev/null | head -1 || true)"
    if [[ -n "$a_rec" ]]; then
        die "域名 $AGH_DOH_HOST 已有 A 记录（解析到 $a_rec）。同一域名不能同时有 A 记录和 CNAME，隧道需要创建 CNAME 记录。请先去 Cloudflare DNS 里删掉这条 A 记录，或换一个没有被占用的子域名，再重新运行本脚本。"
    fi

    info "添加隧道 DNS 路由（自动创建指向隧道的 CNAME 记录）..."
    cloudflared tunnel route dns "$AGH_TUNNEL_NAME" "$AGH_DOH_HOST" \
        || die "添加隧道 DNS 路由失败。如果提示 DNS 记录已存在，请去 Cloudflare DNS 里检查 ${AGH_DOH_HOST} 的记录。"

    write_tunnel_config "$tunnel_id"

    if ! systemctl list-unit-files --no-legend 2>/dev/null | grep -q '^cloudflared\.service'; then
        info "安装 cloudflared 系统服务..."
        cloudflared service install || die "安装 cloudflared 系统服务失败。"
    fi
    systemctl enable cloudflared >/dev/null 2>&1 || true
    systemctl restart cloudflared || die "cloudflared 服务启动失败，请查看：journalctl -u cloudflared -n 100"
    sleep 3
    systemctl is-active --quiet cloudflared || die "cloudflared 服务未正常运行。"
    ok "cloudflared 隧道已运行。"
    TUNNEL_ID="$tunnel_id"

    {
        echo "# Cloudflare Tunnel（模式 3，生成时间：$(date -Is)）"
        echo "tunnel_name=${AGH_TUNNEL_NAME}"
        echo "tunnel_id=${tunnel_id}"
        echo "doh_host=${AGH_DOH_HOST}"
    } >> "$CRED_FILE"
    chmod 600 "$CRED_FILE"
}

# ---------------------------------------------------------------- 模式 4：trycloudflare 快速隧道兜底
setup_quick_tunnel() {
    # 模式 4 兜底：免费快速隧道，无需登录、无需账号。
    # 返回 0 = 隧道已启动并拿到域名（AGH_DOH_HOST 被设为 trycloudflare 域名，
    # MODE4_PATH 被设为 tunnel）；返回 1 = 失败（调用方报错退出）。
    # 注意：快速隧道域名每次重启服务会变，变了要更新客户端配置；
    # 想要固定域名请用模式 3（需要 Cloudflare 账号）。
    install_cloudflared
    cat > /etc/systemd/system/adguard-quick-tunnel.service <<EOF
# AdGuard DoH 快速隧道（由一键部署脚本生成，模式 4 兜底）
[Unit]
Description=AdGuard DoH quick tunnel (trycloudflare)
After=network-online.target AdGuardHome.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel --url https://127.0.0.1:8090 --no-tls-verify
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable adguard-quick-tunnel >/dev/null 2>&1 || true
    systemctl restart adguard-quick-tunnel \
        || { warn "快速隧道服务启动失败，请查看：journalctl -u adguard-quick-tunnel -n 100"; return 1; }

    # 等 cloudflared 在日志里打出分配的域名（形如 https://xxx.trycloudflare.com），最多等 90 秒。
    # 取最新的一条：服务每次重启都会重新打一条，旧的域名已失效，不能用。
    # 排除 api.trycloudflare.com：那是 cloudflared 请求隧道的 API 端点（出错时也会出现在日志里），不是分配的隧道域名。
    local host="" i=0
    for i in $(seq 1 45); do
        host="$(journalctl -u adguard-quick-tunnel --no-pager -n 200 2>/dev/null \
            | grep -oE 'https://[A-Za-z0-9-]+\.trycloudflare\.com' \
            | grep -v 'https://api\.trycloudflare\.com' \
            | tail -1 | sed 's#https://##' || true)"
        if [[ -n "$host" ]]; then break; fi
        sleep 2
    done
    if [[ -z "$host" ]]; then
        warn "快速隧道启动后 90 秒内没有拿到 trycloudflare 域名，请查看：journalctl -u adguard-quick-tunnel -n 100"
        return 1
    fi
    AGH_DOH_HOST="$host"
    MODE4_PATH="tunnel"

    {
        echo "# trycloudflare 快速隧道（模式 4 兜底，生成时间：$(date -Is)）"
        echo "quick_tunnel_host=${host}"
        echo "doh_host=${host}"
        echo "doh_url=https://${host}/dns-query"
    } >> "$CRED_FILE"
    chmod 600 "$CRED_FILE"
    ok "快速隧道已运行：https://${host}/dns-query"
    warn "注意：快速隧道域名每次重启 adguard-quick-tunnel 服务会变，变了要更新客户端配置；想要固定域名请用模式 3。"
    return 0
}

# ---------------------------------------------------------------- 验证与汇总
check_doh_dns() {
    # 模式 2 才需要：DoH 域名必须解析到本机，否则客户端连不上
    local ip="" resolved=""
    ip="$(server_ip)"
    resolved="$(dig +short "$AGH_DOH_HOST" A 2>/dev/null | tr '\n' ' ' || true)"
    if [[ -z "$resolved" ]]; then
        warn "域名 $AGH_DOH_HOST 目前解析不到任何 IP（DNS 可能还没生效，或 A 记录还没加）。"
        warn "请去 Cloudflare DNS 给 $AGH_DOH_HOST 加一条 A 记录指向本机 IP：$ip，然后再验证。"
        return 1
    fi
    if [[ "$resolved" != *"$ip"* ]]; then
        warn "域名 $AGH_DOH_HOST 解析到 $resolved，但本机 IP 是 $ip，两者不一致，客户端可能连不上。"
        return 1
    fi
    ok "域名解析正常：$AGH_DOH_HOST -> $resolved"
    return 0
}

verify_doh() {
    local url="https://${AGH_DOH_HOST}/dns-query?dns=${DOH_QUERY_B64}"
    info "验证 DoH 查询：$url"
    local resp="" i=0
    # --noproxy '*'：DoH 域名指向本机，必须直连，不能走环境里可能存在的代理。
    # AdGuard/nginx 刚重启完可能还没就绪，最多等 30 秒，每 2 秒重试一次。
    for i in $(seq 1 15); do
        resp="$(curl -s -i --noproxy '*' --max-time 15 "$url" -H 'accept: application/dns-message' 2>&1 || true)"
        if printf '%s' "$resp" | grep -qi 'application/dns-message' \
            && printf '%s' "$resp" | grep -q ' 200 '; then
            echo "$resp" | head -8
            ok "DoH 验证通过：返回 HTTP 200 application/dns-message（有效的 DNS 答案）。"
            return 0
        fi
        sleep 2
    done
    echo "$resp" | head -8
    warn "DoH 验证未通过（上面是 curl 的实际返回）。"
    warn "可能原因：DNS 还没生效（等几分钟再测）、证书还没被信任、隧道还没连上。"
    warn "提示：空查询返回 HTTP 400 是正常的，那是 AdGuard 对无 dns 参数请求的回应，不是故障。"
    return 1
}

print_summary() {
    local ip=""
    ip="$(server_ip)"
    echo
    echo "==================== 部署完成 ===================="
    echo "模式：$MODE_TEXT"
    echo "管理面板：http://${ip}:${AGH_ADMIN_PORT}/（用户名：${AGH_ADMIN_USER}）"
    echo "明文 DNS：${ip}（UDP/TCP 53）"
    if [[ "$MODE" == "2" ]]; then
        echo "DoH 地址：https://${AGH_DOH_HOST}/dns-query"
        echo "DoT 地址：tls://${AGH_DOH_HOST}:${DOT_PORT}"
        echo "证书目录：/etc/ssl/${AGH_DOH_HOST}/（acme.sh 自动续期并重载）"
        if [[ "$SINGBOX_INSTALLED" == "y" ]]; then
            echo "sing-box VLESS+REALITY：443 端口（非 REALITY 握手回落到 nginx DoH）"
        fi
    fi
    if [[ "$MODE" == "3" ]]; then
        echo "DoH 地址：https://${AGH_DOH_HOST}/dns-query（经 Cloudflare Tunnel）"
        echo "隧道：${AGH_TUNNEL_NAME}（ID：${TUNNEL_ID:-未知}）"
        echo "隧道配置：$HOME/.cloudflared/config.yml"
    fi
    if [[ "$MODE" == "4" ]]; then
        if [[ "$MODE4_PATH" == "direct" ]]; then
            echo "DoH 地址：https://${AGH_DOH_HOST}/dns-query（直连）"
            echo "DoT 地址：tls://${AGH_DOH_HOST}:853"
            echo "DoQ 地址：quic://${AGH_DOH_HOST}:853"
            echo "证书目录：/etc/ssl/${AGH_DOH_HOST}/（acme.sh 自动续期并重载）"
        else
            echo "DoH 地址：https://${AGH_DOH_HOST}/dns-query（经 trycloudflare 快速隧道）"
            echo "快速隧道服务：adguard-quick-tunnel.service（查看日志：journalctl -u adguard-quick-tunnel -n 100）"
            echo "注意：快速隧道域名每次重启服务会变，变了要更新客户端配置；想要固定域名请用模式 3。"
        fi
    fi
    echo "凭据文件：$CRED_FILE（权限 600，只在本地）"
    echo "AdGuard 配置：$AGH_CONF"
    echo "查看日志：journalctl -u AdGuardHome -n 100"
    echo "=================================================="
    echo "下一步：在 AdGuard 查询日志里确认有新记录，类型应为 DNS-over-HTTPS。"
    echo "切换模式：重新运行本脚本选另一个模式即可，管理员账号会被保留。"
}

# ---------------------------------------------------------------- 主流程
main() {
    check_root
    check_os
    choose_mode
    prompt_common

    # 通用凭据文件头（只记非敏感信息，不记密码和 Token）
    {
        echo "# AdGuard Home 一键部署凭据（生成时间：$(date -Is)）"
        echo "# 注意：管理员密码和 Cloudflare API Token 不会写进这个文件。"
        echo "mode=${MODE}"
        echo "admin_user=${AGH_ADMIN_USER}"
        echo "admin_port=${AGH_ADMIN_PORT}"
    } > "$CRED_FILE"
    chmod 600 "$CRED_FILE"

    case "$MODE" in
        1)
            MODE_TEXT="1 明文"
            TLS_ENABLED="false"
            TLS_SERVER_NAME=""
            TLS_CERT=""
            TLS_KEY=""
            install_adguard
            write_agh_config
            start_adguard
            ;;
        2)
            MODE_TEXT="2 加密直连 DoH"
            prompt_mode2
            TLS_ENABLED="true"
            TLS_SERVER_NAME="$AGH_DOH_HOST"
            TLS_CERT="/root/.acme.sh/${AGH_DOH_HOST}_ecc/fullchain.cer"
            TLS_KEY="/root/.acme.sh/${AGH_DOH_HOST}_ecc/${AGH_DOH_HOST}.key"
            install_adguard
            install_acme
            issue_cert
            write_agh_config
            start_adguard
            if [[ "$AGH_INSTALL_SINGBOX" == "y" ]]; then
                SINGBOX_INSTALLED="y"
                write_nginx_vhost "127.0.0.1:8443"
                install_singbox
                setup_singbox_reality
            else
                write_nginx_vhost "443"
            fi
            check_doh_dns || true
            verify_doh || true
            ;;
        3)
            MODE_TEXT="3 加密经 Cloudflare Tunnel"
            prompt_mode3
            TLS_ENABLED="true"
            TLS_SERVER_NAME="$AGH_DOH_HOST"
            TLS_CERT=""
            TLS_KEY=""
            install_adguard
            write_agh_config
            start_adguard
            install_cloudflared
            setup_tunnel
            verify_doh || true
            ;;
        4)
            MODE_TEXT="4 零依赖加密（直连优先，失败走快速隧道）"
            prompt_mode4
            DOT_PORT="853"
            DOQ_PORT="853"
            install_adguard
            if [[ "$AGH_FORCE_TUNNEL" == "y" ]]; then
                # 强制走隧道：AdGuard 开 TLS 但不填证书路径（自签名），
                # 快速隧道用 --no-tls-verify 连本机 8090。
                TLS_ENABLED="true"
                TLS_SERVER_NAME="adguard"
                TLS_CERT=""
                TLS_KEY=""
                write_agh_config
                start_adguard
                setup_quick_tunnel || die "快速隧道启动失败：请检查网络与日志 journalctl -u adguard-quick-tunnel -n 100。"
                verify_doh || die "快速隧道 DoH 验证失败（https://${AGH_DOH_HOST}/dns-query 未返回有效 DNS 答案）。请检查 journalctl -u AdGuardHome -n 100 与 journalctl -u adguard-quick-tunnel -n 100。"
            else
                # 直连：公网 IP -> sslip.io 域名 -> Let's Encrypt HTTP-01 签证书。
                local pub_ip=""
                pub_ip="$(public_ip)" || die "无法获取本机公网 IP（外网 IP 查询服务连不上，且本机网卡 IP 不是公网 IP）。模式 4 需要公网 IP 生成 sslip.io 域名；如果这台 VPS 没有公网 IP，请用模式 1 或模式 3。"
                AGH_DOH_HOST="$(printf '%s' "$pub_ip" | tr '.' '-').sslip.io"
                info "本机公网 IP：$pub_ip，直连 DoH 域名：$AGH_DOH_HOST（sslip.io 自动解析到本机，无需注册域名）。"
                # sslip.io 是通配解析，正常应立即解析到本机 IP；先轻量检查一次，
                # 解析不对只警告（证书签发本身会再校验一次，失败会走隧道兜底）。
                local resolved=""
                resolved="$(dig +short "$AGH_DOH_HOST" A 2>/dev/null | head -1 || true)"
                if [[ "$resolved" != "$pub_ip" ]]; then
                    warn "域名 $AGH_DOH_HOST 目前解析到 ${resolved:-（无结果）}，不是本机公网 IP $pub_ip，证书签发可能失败。"
                fi
                TLS_ENABLED="true"
                TLS_SERVER_NAME="$AGH_DOH_HOST"
                TLS_CERT="/root/.acme.sh/${AGH_DOH_HOST}_ecc/fullchain.cer"
                TLS_KEY="/root/.acme.sh/${AGH_DOH_HOST}_ecc/${AGH_DOH_HOST}.key"
                install_acme
                local direct_ok="n"
                write_nginx_http01_vhost
                if issue_cert_http01; then
                    write_agh_config
                    start_adguard
                    write_nginx_vhost "443"
                    if verify_doh; then
                        direct_ok="y"
                        MODE4_PATH="direct"
                        {
                            echo "# 直连 DoH（模式 4，生成时间：$(date -Is)）"
                            echo "doh_host=${AGH_DOH_HOST}"
                            echo "doh_url=https://${AGH_DOH_HOST}/dns-query"
                        } >> "$CRED_FILE"
                        chmod 600 "$CRED_FILE"
                    else
                        warn "直连 DoH 验证失败（https://${AGH_DOH_HOST}/dns-query 未返回有效答案），可能 443 被运营商拦截，自动切到快速隧道兜底。"
                    fi
                else
                    warn "证书签发失败，自动切到快速隧道兜底（不需要 80/443 直连）。"
                    # 证书没拿到：AdGuard 改用自签名证书（TLS 开，证书路径留空），
                    # 快速隧道用 --no-tls-verify 连本机 8090。
                    TLS_CERT=""
                    TLS_KEY=""
                    write_agh_config
                    start_adguard
                fi
                if [[ "$direct_ok" != "y" ]]; then
                    setup_quick_tunnel || die "直连和快速隧道都失败了：直连失败原因见上面的证书/验证提示；隧道失败请检查 journalctl -u adguard-quick-tunnel -n 100。"
                    verify_doh || die "直连和快速隧道都失败了：隧道已启动，但 DoH 验证未通过（https://${AGH_DOH_HOST}/dns-query 未返回有效 DNS 答案）。请检查 journalctl -u AdGuardHome -n 100 与 journalctl -u adguard-quick-tunnel -n 100。"
                fi
            fi
            ;;
        *)
            die "未知模式：$MODE"
            ;;
    esac

    print_summary
}

# 直接执行本文件时跑主流程；被 source 引用时只加载函数（方便测试）。
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
