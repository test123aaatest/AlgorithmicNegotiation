#!/bin/bash
# ============================================================
# 设计约束：
#   - 不新增原 4 脚本之外的实际测试算法
#   - 自动识别发行版/SSH 版本；识别失败不测试，正常退出
#   - 必须 root（--list 除外）
#   - 默认端口 22
#   - 保留手动模式；--auto 使用本地 127.0.0.1
#   - 每次只修改一个测试配置，测试完成后恢复
#   - 协商结果与认证结果分离
#   - 算法结果不与 SSH 客户端退出码直接绑定
#   - 保留详细测试日志、环境/执行信息、结构化结果
#
# 输出（当前目录）：
#   默认：1 个 CSV + 1 个详细 TXT + 1 个环境/执行 TXT
#   --json：改为 1 个 JSON + 1 个详细 TXT + 1 个环境/执行 TXT
#
# 功能：自动探测当前运行环境（OpenSSH 版本 + init 系统），据此
# 选择并运行对应的算法兼容性测试集，全程共用同一套备份/崩溃自愈/
# 恢复框架。
#
# 环境画像（完全自动探测，不支持手动指定）：
#   centos6   OpenSSH < 6.x + SysV init（如 CentOS 6.10 / OpenSSH 5.3）
#             自动依次运行：SSH-2 遗留算法测试 + SSH-1 协议测试
#             （同一时刻服务器只跑一种协议配置，两套测试不冲突）
#   openssh8  OpenSSH 8.x + systemd（如 AlmaLinux/Rocky 9、Ubuntu 22.04、
#             Debian 12），测试 AlmaLinux 10 构建未启用的 OpenSSH 8.x
#             特有算法（当前只有 curve448-sha512/X448）
#   modern    OpenSSH >= 9.x + systemd（如 AlmaLinux 10），测试现代
#             算法全集（AEAD/CTR/CBC/KEX/HostKey/MAC，含后量子 KEX）
#
# 环境不属于以上任何一类时，脚本不会对系统做任何改动，只打印诊断信息并退出。
#
# 用法（四种模式，所有环境画像下都支持）：
#   sudo ./test_ssh_algorithms_all.sh                # 手动模式（默认，每项测试需手动触发/确认）
#   sudo ./test_ssh_algorithms_all.sh --auto          # 自动模式（本地回环客户端自动触发）
#   sudo ./test_ssh_algorithms_all.sh --list          # 只列出当前环境的测试项，不改动系统
#   sudo ./test_ssh_algorithms_all.sh --only=3        # 只运行编号为 3 的测试项（可与 --auto 组合）
#   sudo ./test_ssh_algorithms_all.sh --only=blowfish # 只运行描述包含 blowfish 的测试项
#
# 安全提示：
#   - 运行期间会临时开启 PermitRootLogin yes / PasswordAuthentication yes。
#   - trap 已覆盖 INT/TERM/EXIT，正常退出、Ctrl+C、kill 都会自动恢复配置。
#   - sshd_config 的每一次写入都是"临时文件校验通过后再原子替换"，线上
#     配置任何时刻要么是上一个合法状态、要么是新的合法状态。
#   - 崩溃自愈机制按 init 系统自动选择实现：
#       systemd 环境：systemd drop-in 的 ExecStartPre 钩子，在 sshd.service
#                     每次启动前检查并按需恢复备份（覆盖脚本被 kill -9 /
#                     断电重启等场景）。
#       SysV 环境（如 CentOS 6）：crontab @reboot 尽力而为的开机自愈检查，
#                     不能像 systemd 那样保证抢在 sshd 之前执行，只能做到
#                     "开机后尽快"。
#   - kill -9 / 断电 / 文件系统损坏等极端情况仍可能让配置停留在测试状态，
#     建议运行前用防火墙临时限制 22 端口来源，并确保有控制台/IPMI 等
#     带外访问方式作为最后手段。
# ============================================================

set -u
set -o pipefail

# bash 4+ 关联数组（declare -A）检查
(( BASH_VERSINFO[0] >= 4 )) || { echo "错误：需要 bash 4+（当前 ${BASH_VERSION}）。"; exit 1; }

BASE_DIR="$(pwd)"
TS="$(date +%Y%m%d_%H%M%S)"

RESULT_FORMAT="csv"
AUTO=false
LIST_ONLY=false
CRYPTO_POLICY_TOOL=""
CRYPTO_POLICY_MODE="${CRYPTO_POLICY_MODE:-capability}"

ONLY_FILTER=""

SSHD_CONFIG="/etc/ssh/sshd_config"
STATE_ROOT="/var/lib/ssh-algo-unified"
STATE_DIR="${STATE_ROOT}/${TS}_$$"
LOCK_DIR="/var/run/ssh-algo-unified.lock"
BACKUP_FILE="${STATE_DIR}/sshd_config.backup"
AUTO_KEY="/tmp/algo_test_key.$$"
AUTO_PUB="${AUTO_KEY}.pub"
AUTO_SSH1_KEY="/tmp/algo_test_ssh1_key.$$"
AUTO_SSH1_PUB="${AUTO_SSH1_KEY}.pub"
AUTO_MARKER="algo-test-auto-key"
LOOPBACK_TARGET="root@127.0.0.1"
# 默认高位端口，避免碰生产 22；可用 --port= 覆盖
PORT=22

LOG_FILE="${BASE_DIR}/ssh_algorithm_test_${TS}.txt"
ENV_FILE="${BASE_DIR}/ssh_algorithm_env_${TS}.txt"
CSV_FILE="${BASE_DIR}/ssh_algorithm_results_${TS}.csv"
JSON_FILE="${BASE_DIR}/ssh_algorithm_results_${TS}.json"

RESTORED=false
# 恢复失败标记：任意恢复步骤失败即中止脚本并带非零退出码退出，
# 避免 sshd 以测试配置继续运行导致后续测试全部失真。
RESTORE_FAILED=false
CLIENT_PID=""
TEST_INDEX=0
RUN_INDEX=0
PASS=0
FAIL=0
UNKNOWN=0
SKIP=0
FILTERED_TESTS=0
WORKER_ALGORITHM_FILE="内置于测试脚本"
WORKER_CIPHERS=""
WORKER_KEX=""
WORKER_MACS=""
WORKER_HOSTKEYS=""
WORKER_SSH1_CIPHERS=""
DEFAULT_KEX=""
DEFAULT_CIPHER=""
DEFAULT_MAC=""
DEFAULT_HOSTKEY=""
DEFAULT_HOSTKEY_ALGORITHMS=""
DEFAULT_CONFIG_LOADED=false

INITIAL_SERVICE_ACTIVE=false
INITIAL_SERVICE_KNOWN=false
INITIAL_CRYPTO_POLICY=""
CRYPTO_POLICY_CHANGED=false
GENERATED_HOST_KEYS=()
# 记录本测试覆盖前已存在的原文件备份（RESTORE_HELPER / systemd drop-in 等），
# 恢复时原样还原，避免覆盖/删除管理员已有配置。
PREEXISTING_BACKUPS=()
# 本测试创建的所有临时文件清单，恢复时精确删除，避免按 glob 误删其它进程文件。
TRACKED_TMP_FILES=()
AUTO_AUTH_KEY_ADDED=false
RESTORE_HELPER="/usr/local/sbin/ssh-algo-unified-restore"
PID_FILE="/var/run/ssh-algo-unified.pid"
SYSTEMD_DROPIN_DIR=""
SYSTEMD_DROPIN_FILE=""
CRON_TAG="# SSH_ALGO_UNIFIED_RECOVERY"
STATE_DIR_CREATED=false
RECOVERY_INSTALLED=false
LOCK_ACQUIRED=false

OS_ID="unknown"
OS_VERSION_ID="unknown"
OS_PRETTY="unknown"
SSH_VERSION_STR=""
SSH_VER=""
SSH_VER_MAJOR=""
SSH_VER_MINOR=""
SSHD_VER=""
SSHD_BIN=""
SSHD_VER_MAJOR=""
SSHD_VER_MINOR=""
SERVICE="unknown"
INIT="unknown"
PROFILE="unknown"

declare -a DESCS KEXES CIPHERS MACS HOSTKEYS TEST_GROUPS PROTOCOLS COMPRESSIONS DEFAULT_FLAGS
# 跨 loader 共享的去重集合：所有动态生成器共用，避免 openssh8 等多 loader
# 场景下不同生成器产生重复四元组。bash 关联数组，需 bash>=4。
declare -A GLOBAL_SEEN

detect_crypto_policy_tool() {
    CRYPTO_POLICY_TOOL=""
    if command -v update-crypto-policies >/dev/null 2>&1; then
        CRYPTO_POLICY_TOOL="$(command -v update-crypto-policies)"
    fi
}

crypto_policy_requires_relaxation() {
    # --list must never mutate host state.
    [[ "$LIST_ONLY" != true ]] || return 1
    # Only capability mode may change system crypto policy.
    [[ "$CRYPTO_POLICY_MODE" == "capability" ]] || return 1
    [[ -n "$CRYPTO_POLICY_TOOL" ]] || return 1
    [[ -n "$INITIAL_CRYPTO_POLICY" ]] || return 1

    # LEGACY is a RHEL-family mechanism. Do not assume it on
    # arbitrary distributions even when a similarly named command exists.
    case "$PROFILE" in
        modern|openssh8)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

crypto_policy_relax_for_test() {
    crypto_policy_requires_relaxation || return 0

    # Already permissive enough; do not change it.
    case "$INITIAL_CRYPTO_POLICY" in
        LEGACY|LEGACY:*)
            return 0
            ;;
    esac

    log "Temporarily switching crypto policy from '$INITIAL_CRYPTO_POLICY' to 'LEGACY' for capability test"
    if "$CRYPTO_POLICY_TOOL" --set LEGACY >/dev/null 2>&1; then
        CRYPTO_POLICY_CHANGED=true
        return 0
    fi

    warn "Unable to switch crypto policy to LEGACY; continuing with the original policy"
    return 1
}

for arg in "$@"; do
    case "$arg" in
        --auto)
            AUTO=true
            ;;
        --list)
            LIST_ONLY=true
            ;;
        --only=*)
            ONLY_FILTER="${arg#--only=}"
            ;;
        --json)
            RESULT_FORMAT="json"
            ;;
        --csv)
            RESULT_FORMAT="csv"
            ;;
        --port=*)
            PORT="${arg#--port=}"
            if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
                echo "错误：--port 必须是 1-65535 的纯数字（收到: '$PORT'）" >&2
                exit 1
            fi
            ;;
        -h|--help)
            cat <<'EOF'
用法: sudo ./test_ssh_algorithms_all.sh [选项]

选项:
  (无参数)           手动模式（默认，每项测试需手动触发/确认）
  --auto             自动模式（本地回环客户端自动触发）
  --list             只列出当前环境的测试项，不改动系统
  --only=N           只运行编号为 N 的测试项（可与 --auto 组合）
  --only=keyword     只运行描述包含 keyword 的测试项
  --json             结果文件改为 JSON 格式
  --csv              结果文件改为 CSV 格式（默认）
  --port=N           指定测试端口（默认 22）
  -h, --help         显示此帮助信息
EOF
            exit 0
            ;;
        *)
            echo "警告：未识别参数 '$arg'，已忽略" >&2
            ;;
    esac
done

if ! $LIST_ONLY && [[ $EUID -ne 0 ]]; then
    echo "错误：必须以 root 身份运行。"
    exit 1
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

log() {
    if [[ -f "$LOG_FILE" ]]; then
        printf '%s\n' "$*" | tee -a "$LOG_FILE"
    else
        printf '%s\n' "$*"
    fi
}

env_log() {
    [[ -f "$ENV_FILE" ]] && printf '%s\n' "$*" >> "$ENV_FILE"
}

csv_escape() {
    local s="${1:-}"
    s=${s//\"/\"\"}
    printf '"%s"' "$s"
}

json_escape() {
    local s="${1:-}"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$s" | jq -Rs '.' | sed 's/^"//;s/"$//'
        return
    fi
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//$'\b'/\\b}
    s=${s//$'\f'/\\f}
    # 移除其它不可打印控制字符（0x00-0x1F 除已处理的），避免生成非法 JSON
    s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
    printf '%s' "$s"
}

die() {
    log "[错误] $*"
    exit 1
}

warn() {
    log "[警告] $*"
}

detect_env() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION_ID="${VERSION_ID:-unknown}"
        OS_PRETTY="${PRETTY_NAME:-unknown}"
    elif [[ -r /etc/redhat-release ]]; then
        OS_PRETTY="$(cat /etc/redhat-release)"
        OS_ID="redhat-family"
        OS_VERSION_ID="$(sed -n 's/.*release \([0-9.]*\).*/\1/p' /etc/redhat-release)"
    fi

    if command -v ssh >/dev/null 2>&1; then
        SSH_VERSION_STR="$(ssh -V 2>&1 || true)"
        # 用 bash 内置正则解析版本号，不依赖 sed；同时兼容没有次版本号的
        # 写法（如假设中的 "OpenSSH_10"）
        if [[ "$SSH_VERSION_STR" =~ OpenSSH_([0-9]+)(\.([0-9]+))? ]]; then
            SSH_VER_MAJOR="${BASH_REMATCH[1]}"
            SSH_VER_MINOR="${BASH_REMATCH[3]:-0}"
            SSH_VER="${SSH_VER_MAJOR}.${SSH_VER_MINOR}"
        else
            SSH_VER=""
            SSH_VER_MAJOR=""
        fi
    else
        SSH_VERSION_STR="未找到 ssh 客户端"
        SSH_VER=""
        SSH_VER_MAJOR=""
        SSH_VER_MINOR=""
    fi
    if SSHD_BIN="$(command -v sshd 2>/dev/null)" && [[ -n "$SSHD_BIN" ]]; then
        SSHD_VER="$("$SSHD_BIN" -V 2>&1 || true)"
        if [[ "$SSHD_VER" =~ OpenSSH_([0-9]+)(\.([0-9]+))? ]]; then
            SSHD_VER_MAJOR="${BASH_REMATCH[1]}"
            SSHD_VER_MINOR="${BASH_REMATCH[3]:-0}"
        fi
    else
        SSHD_VER="未找到 sshd"
        SSHD_BIN=""
        SSHD_VER_MAJOR=""
        SSHD_VER_MINOR=""
    fi

    # sshd -V 在 OpenSSH < 7.2 上不支持（如 CentOS 6 / OpenSSH 5.3），
    # 会导致 SSHD_VER_MAJOR 为空。此时仅在典型的 SysV/CentOS6 场景下回退到
    # 客户端版本号（同一系统上客户端和服务端版本通常一致）；若系统是
    # systemd 现代环境却拿不到 sshd 版本，不回退，避免用客户端版本误判。
    if [[ -z "$SSHD_VER_MAJOR" ]] && [[ -n "$SSH_VER_MAJOR" ]] && [[ "$INIT" == "sysv/service" ]]; then
        SSHD_VER_MAJOR="$SSH_VER_MAJOR"
        SSHD_VER_MINOR="${SSH_VER_MINOR:-0}"
        env_log "sshd -V 不可用（OpenSSH < 7.2），在 SysV 环境回退到客户端版本: ${SSH_VER}"
    fi

    # 判定 init 系统的关键：systemctl 命令存在并不代表 systemd 真正可用。

    if command -v systemctl >/dev/null 2>&1; then
        # is-system-running 在 degraded 状态返回 1，但 systemd 仍在正常运行。
        # 用 /run/systemd/system 目录或 PID1 是否为 systemd 来判定，而非
        # 依赖 is-system-running 的退出码（容器中 PID1 不是 systemd）。
        if [[ -d /run/systemd/system ]] || [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]]; then
            local unit_list
            unit_list="$(systemctl list-unit-files 2>/dev/null || true)"
            if printf '%s\n' "$unit_list" | grep -q '^sshd\.service'; then
                INIT="systemd"
                SERVICE="sshd"
            elif printf '%s\n' "$unit_list" | grep -q '^ssh\.service'; then
                INIT="systemd"
                SERVICE="ssh"
            fi
        else
            env_log "systemctl 存在但 systemd PID1 不可用，回退到 SysV service"
        fi
    fi
    if [[ "$INIT" == "unknown" ]] && command -v service >/dev/null 2>&1; then
        INIT="sysv/service"
        if service --status-all 2>&1 | grep -qiE '^[[:space:]]*\?[[:space:]]+sshd'; then
            SERVICE="sshd"
        elif service --status-all 2>&1 | grep -qiE '^[[:space:]]*\?[[:space:]]+ssh$'; then
            SERVICE="ssh"
        elif [[ -x /etc/init.d/sshd ]]; then
            SERVICE="sshd"
        elif [[ -x /etc/init.d/ssh ]]; then
            SERVICE="ssh"
        else
            SERVICE="sshd"
        fi
    fi

    # ---- 画像判定：以 sshd 主版本号 + init 系统为准，不依赖客户端版本。
    # 目标是测试服务器能力，不能用本机 ssh 客户端版本代替服务端版本。
    #
    # 没有可用的服务管理命令（systemctl/service 都不存在）时，无法重启
    # /查询 sshd 状态，即使版本号匹配也判 unknown，避免后面每一项测试
    # 都因为"不知道怎么重启服务"而失败。
    if [[ "$INIT" == "unknown" ]]; then
        PROFILE="unknown"
        return 1
    fi
    if [[ "$INIT" == "systemd" && "$SERVICE" == "unknown" ]]; then
        PROFILE="unknown"
        return 1
    fi

    # ---- openEuler 国密环境检测（优先于版本号判定）----
    if [[ "$OS_ID" =~ ^openeuler$ ]] || grep -qi "openeuler" /etc/os-release 2>/dev/null; then
        PROFILE="openeuler"
        return 0
    fi

    if [[ -n "$SSHD_VER_MAJOR" ]] && (( SSHD_VER_MAJOR < 6 )) && [[ "$INIT" == "sysv/service" ]]; then
        PROFILE="centos6"
        return 0
    fi

    if [[ "$SSHD_VER_MAJOR" == 8 ]]; then
        PROFILE="openssh8"
        return 0
    fi

    if [[ -n "$SSHD_VER_MAJOR" ]] && (( SSHD_VER_MAJOR >= 9 )); then
        PROFILE="modern"
        return 0
    fi

    PROFILE="unknown"
    return 1
}

load_worker_algorithms() {
    # 这是 Worker 已实现的完整算法基线
    WORKER_SSH1_CIPHERS=$'3des\nblowfish\nidea\narcfour\ndes'
    WORKER_CIPHERS=$'chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\naes128-gcm@openssh.com\naes256-ctr\naes192-ctr\nsm4-ctr\naes128-ctr\naes256-cbc\naes192-cbc\naes128-cbc\nrijndael-cbc@lysator.liu.se\ntwofish256-cbc\ntwofish128-cbc\n3des-ctr\n3des-cbc\ncast128-cbc\nblowfish-cbc\narcfour256\narcfour128\narcfour\ndes-cbc'
    WORKER_KEX=$'mlkem768x25519-sha256\nsntrup761x25519-sha512@openssh.com\nsntrup761x25519-sha512\ncurve25519-sha256\ncurve25519-sha256@libssh.org\ncurve448-sha512\necdh-sha2-nistp521\necdh-sha2-nistp384\necdh-sha2-nistp256\nsm2-sm3\nsm2_sm3\nsm2kex\ndiffie-hellman-group18-sha512\ndiffie-hellman-group17-sha512\ndiffie-hellman-group16-sha512\ndiffie-hellman-group15-sha512\ndiffie-hellman-group-exchange-sha512\ndiffie-hellman-group14-sha256\ndiffie-hellman-group-exchange-sha256\ndiffie-hellman-group14-sha1\ndiffie-hellman-group-exchange-sha1\ndiffie-hellman-group5-sha1\ndiffie-hellman-group2-sha1\ndiffie-hellman-group1-sha1\necdh-sha2-nistb409\necdh-sha2-nistb233\necdh-sha2-nistk163'
    WORKER_HOSTKEYS=$'ssh-ed25519-cert-v01@openssh.com\nssh-ed448\nssh-ed25519\nssh-sm2\nsm2\necdsa-sha2-nistp521-cert-v01@openssh.com\necdsa-sha2-nistp384-cert-v01@openssh.com\necdsa-sha2-nistp256-cert-v01@openssh.com\necdsa-sha2-nistp521\necdsa-sha2-nistp384\necdsa-sha2-nistp256\nrsa-sha2-512-cert-v01@openssh.com\nrsa-sha2-256-cert-v01@openssh.com\nrsa-sha2-512\nrsa-sha2-256\nssh-rsa-cert-v01@openssh.com\nssh-rsa\nssh-dss-cert-v01@openssh.com\nssh-dss'
    WORKER_MACS=$'hmac-sha2-512-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\nhmac-sm3-etm@openssh.com\numac-128-etm@openssh.com\numac-64-etm@openssh.com\nhmac-sha2-512\nhmac-sha2-256\nhmac-sm3\numac-128@openssh.com\numac-64@openssh.com\nhmac-ripemd160-etm@openssh.com\nhmac-ripemd160@openssh.com\nhmac-sha1-etm@openssh.com\nhmac-sha1\nhmac-sha1-96-etm@openssh.com\nhmac-sha1-96\nhmac-md5-etm@openssh.com\nhmac-md5\nhmac-md5-96-etm@openssh.com\nhmac-md5-96'
    return 0
}

load_default_effective_algorithms() {
    local output
    [[ "$DEFAULT_CONFIG_LOADED" == true ]] && return 0
    DEFAULT_CONFIG_LOADED=true
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 1
    output="$("$SSHD_BIN" -T -f "$SSHD_CONFIG" 2>/dev/null)" || return 1
    DEFAULT_KEX="$(printf '%s\n' "$output" | awk '$1 == "kexalgorithms" { print $2 }' | tr ',' '\n')"
    DEFAULT_CIPHER="$(printf '%s\n' "$output" | awk '$1 == "ciphers" { print $2 }' | tr ',' '\n')"
    DEFAULT_MAC="$(printf '%s\n' "$output" | awk '$1 == "macs" { print $2 }' | tr ',' '\n')"
    DEFAULT_HOSTKEY="$(printf '%s\n' "$output" | awk '$1 == "hostkey" { print $2 }')"
    DEFAULT_HOSTKEY_ALGORITHMS="$(printf '%s\n' "$output" | awk '$1 == "hostkeyalgorithms" { print $2 }' | tr \, '\n')"
    return 0
}

worker_algorithm_supported() {
    local type="$1" algo="$2" list=""
    # AEAD（chacha20-poly1305 / AES-GCM）等不协商传统 MAC 的 cipher，
    # 其测试组合的 MAC 为空；空算法一律视为"不需要该维度"，放行。
    [[ -n "$algo" ]] && [[ "$type" != "ssh1cipher" ]] || return 0
    case "$type" in
        kex) list="$WORKER_KEX" ;;
        cipher) list="$WORKER_CIPHERS" ;;
        mac) list="$WORKER_MACS" ;;
        hostkey) list="$WORKER_HOSTKEYS" ;;
        ssh1cipher) list="$WORKER_SSH1_CIPHERS" ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$list" | grep -qxF "$algo"
}

default_algorithm_supported() {
    local type="$1" algo="$2" list=""
    case "$type" in
        kex) list="$DEFAULT_KEX" ;;
        cipher) list="$DEFAULT_CIPHER" ;;
        mac) list="$DEFAULT_MAC" ;;
        hostkey)
            # OpenSSH 6.5+ 的 -T 会直接给出 hostkeyalgorithms；优先使用它。
            if [[ -n "$DEFAULT_HOSTKEY_ALGORITHMS" ]] && printf '%s\n' "$DEFAULT_HOSTKEY_ALGORITHMS" | grep -qxF "$algo"; then
                return 0
            fi
            case "$algo" in
                ssh-rsa|ssh-rsa-cert-v01@openssh.com|rsa-sha2-256|rsa-sha2-256-cert-v01@openssh.com|rsa-sha2-512|rsa-sha2-512-cert-v01@openssh.com)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_rsa_key$' && return 0 ;;
                ssh-dss|ssh-dss-cert-v01@openssh.com)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_dsa_key$' && return 0 ;;
                ssh-ed25519|ssh-ed25519-cert-v01@openssh.com)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_ed25519_key$' && return 0 ;;
                ssh-ed448)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_ed448_key$' && return 0 ;;
                ecdsa-*|ecdsa-sha2-nistp256-cert-v01@openssh.com|ecdsa-sha2-nistp384-cert-v01@openssh.com|ecdsa-sha2-nistp521-cert-v01@openssh.com)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_ecdsa_key$' && return 0 ;;
                ssh-sm2|sm2)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_sm2_key$' && return 0 ;;
            esac
            return 1
            ;;
        ssh1cipher) return 0 ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$list" | grep -qxF "$algo"
}

release_algorithm_supported() {
    local type="$1" algo="$2"

    [[ -n "$algo" ]] || return 0

    if [[ "$type" == "ssh1cipher" ]]; then
        case "$algo" in
            3des|blowfish|idea|arcfour|des) return 0 ;;
            *) return 1 ;;
        esac
    fi

    # CentOS 6 的 OpenSSH 5.x 不认识 OpenSSH 6.x 及以后引入的算法。
    if [[ "$PROFILE" == "centos6" ]]; then
        case "$algo" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com|\
            curve25519-sha256|curve25519-sha256@libssh.org|curve448-sha512|\
            mlkem768x25519-sha256|sntrup761x25519-*|ssh-ed25519|ssh-ed448|\
            *-etm@openssh.com|umac-128@openssh.com)
                return 1
                ;;
        esac
    fi

    # OpenSSH 8.x 发行版不应进入 OpenSSH 9.9+ 的后量子/Ed448 测试。
    if [[ "$PROFILE" == "openssh8" ]]; then
        case "$algo" in
            mlkem768x25519-sha256|sntrup761x25519-*|ssh-ed448)
                return 1
                ;;
        esac
    fi

    return 0
}

server_candidate_supported() {
    # 无副作用地验证"当前 sshd 是否能接受该算法组合"。不修改系统配置，
    # 不重启服务；真正测试阶段仍会再次执行 -t/-T。
    local kex="$1" cipher="$2" mac="$3" hostkey="$4" proto="${5:-2}"
    local tmp out hostkey_file
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 2
    [[ "$proto" == "2" ]] || return 0

    case "$hostkey" in
        ssh-dss|ssh-dss-cert-v01@openssh.com) hostkey_file="/etc/ssh/ssh_host_dsa_key" ;;
        ssh-ed25519|ssh-ed25519-cert-v01@openssh.com) hostkey_file="/etc/ssh/ssh_host_ed25519_key" ;;
        ssh-ed448) hostkey_file="/etc/ssh/ssh_host_ed448_key" ;;
        ecdsa-sha2-nistp256|ecdsa-sha2-nistp256-cert-v01@openssh.com|ecdsa-sha2-nistp384|ecdsa-sha2-nistp384-cert-v01@openssh.com|ecdsa-sha2-nistp521|ecdsa-sha2-nistp521-cert-v01@openssh.com) hostkey_file="/etc/ssh/ssh_host_ecdsa_key" ;;
        ssh-sm2|sm2|sm2-cert-v01@openssh.com) hostkey_file="/etc/ssh/ssh_host_sm2_key" ;;
        *) hostkey_file="/etc/ssh/ssh_host_rsa_key" ;;
    esac

    tmp="$(mktemp /tmp/ssh_algo_probe.XXXXXX)" || return 2
    {
        printf '%s\n' '# SSH_ALGO_PROBE'
        printf '%s\n' 'Protocol 2'
        printf '%s\n' "KexAlgorithms $kex"
        printf '%s\n' "Ciphers $cipher"
        # AEAD cipher 不协商传统 MAC，MAC 为空时不写 MACs 指令，
        # 避免 "MACs " 空值使 sshd -t 失败而误过滤掉该 AEAD 测试项。
        if [[ -n "$mac" ]]; then
            printf '%s\n' "MACs $mac"
        fi
        if [[ -n "$SSHD_VER_MAJOR" ]] && { (( SSHD_VER_MAJOR > 6 )) || { (( SSHD_VER_MAJOR == 6 )) && (( SSHD_VER_MINOR >= 5 )); }; }; then
            printf '%s\n' "HostKeyAlgorithms $hostkey"
        fi
        printf '%s\n' "HostKey $hostkey_file"
        cat "$SSHD_CONFIG"
    } > "$tmp"

    if ! "$SSHD_BIN" -t -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"; return 1
    fi
    out="$("$SSHD_BIN" -T -f "$tmp" 2>/dev/null)" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"

    printf '%s\n' "$out" | awk '$1=="kexalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$kex" || return 1
    printf '%s\n' "$out" | awk '$1=="ciphers" {print $2}' | tr ',' '\n' | grep -qxF "$cipher" || return 1
    case "$cipher" in
        chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
        *) printf '%s\n' "$out" | awk '$1=="macs" {print $2}' | tr ',' '\n' | grep -qxF "$mac" || return 1 ;;
    esac

    if printf '%s\n' "$out" | awk '$1=="hostkeyalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$hostkey"; then
        return 0
    fi
    case "$hostkey" in
        ssh-rsa|rsa-sha2-256|rsa-sha2-512) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_rsa_key$' ;;
        ssh-dss) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_dsa_key$' ;;
        ssh-ed25519) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ed25519_key$' ;;
        ssh-ed448) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ed448_key$' ;;
        ecdsa-sha2-*) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ecdsa_key$' ;;
        ssh-sm2|sm2) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_sm2_key$' ;;
        *) return 1 ;;
    esac
}

add_test() {
    # 全局去重：同一 (kex, cipher, mac, hostkey, proto) 只保留首次出现。
    # 统一在 add_test 内部去重，所有 loader 无需各自维护去重集合。
    local _dedup_key="${2}|${3}|${4}|${5}|${7}|${8:-}"
    if [[ -n "${GLOBAL_SEEN[$_dedup_key]:-}" ]]; then
        FILTERED_TESTS=$((FILTERED_TESTS + 1))
        return 0
    fi

    # 第 ① 层：Worker（客户端）能力过滤，始终生效。
    if [[ "$7" == 1 ]]; then
        worker_algorithm_supported ssh1cipher "$3" || {
            FILTERED_TESTS=$((FILTERED_TESTS + 1))
            return 0
        }
    elif ! worker_algorithm_supported kex "$2" ||
         ! worker_algorithm_supported cipher "$3" ||
         ! worker_algorithm_supported mac "$4" ||
         ! worker_algorithm_supported hostkey "$5"; then
        FILTERED_TESTS=$((FILTERED_TESTS + 1))
        return 0
    fi

    # 第 ② 层：目标 sshd 二进制能力过滤（主判据）。
    # server_candidate_supported 用临时配置 + sshd -t/-T 实测该组合能否
    # 被接受（无副作用，不重启不安装）。返回：0=可接受 1=明确不接受
    # 2=无法探测（复用发行版/版本黑名单作兜底，避免硬编码误杀厂商 backport）。
    if [[ "$7" == 2 ]]; then
        server_candidate_supported "$2" "$3" "$4" "$5"
        local src=$?
        if (( src == 1 )); then
            FILTERED_TESTS=$((FILTERED_TESTS + 1))
            return 0
        elif (( src == 2 )); then
            if ! release_algorithm_supported kex "$2" ||
               ! release_algorithm_supported cipher "$3" ||
               ! release_algorithm_supported mac "$4" ||
               ! release_algorithm_supported hostkey "$5"; then
                FILTERED_TESTS=$((FILTERED_TESTS + 1))
                return 0
            fi
        fi
    elif [[ "$7" == 1 ]]; then
        # SSH-1：无 -Q/-T 组合探测，直接走发行版规则。
        release_algorithm_supported ssh1cipher "$3" || {
            FILTERED_TESTS=$((FILTERED_TESTS + 1))
            return 0
        }
    fi

    # 第 ③ 层：当前默认配置（sshd -T 原始配置）实际启用了哪些算法——
    # 这是"类型B（默认配置测试）"维度的标记，不挡测试（挡的是能力），
    # 只作为 CSV/JSON 中 default_supported 列。
    local default_flag="n/a"
    if [[ "$7" == 2 ]] && $DEFAULT_CONFIG_LOADED; then
        # AEAD 加密（chacha20-poly1305 / AES-GCM）不使用传统 MAC，测试组合
        # 里的 MAC 只是占位控制变量；判定"默认配置是否启用"时豁免 MAC。
        local dk=false dc=false dm=true dh=false
        default_algorithm_supported kex "$2" && dk=true
        default_algorithm_supported cipher "$3" && dc=true
        case "$3" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                dm=true ;;
            *) default_algorithm_supported mac "$4" && dm=true ;;
        esac
        default_algorithm_supported hostkey "$5" && dh=true
        if $dk && $dc && $dm && $dh; then
            default_flag="yes"
        else
            default_flag="no"
        fi
    fi

    # 所有过滤检查通过后才标记 GLOBAL_SEEN，避免被过滤的组合
    # 占据去重 key 导致后续同一组合被误判为"重复"而非"能力不足"。
    GLOBAL_SEEN["$_dedup_key"]=1

    DESCS+=("$1")
    KEXES+=("$2")
    CIPHERS+=("$3")
    MACS+=("$4")
    HOSTKEYS+=("$5")
    TEST_GROUPS+=("$6")
    PROTOCOLS+=("$7")
    COMPRESSIONS+=("${8:-}")
    DEFAULT_FLAGS+=("$default_flag")
    TEST_INDEX=$((TEST_INDEX + 1))
}

# ============================================================
# 动态生成：按 Worker 安全排序轮转各维度
# ============================================================

# 单算法能力探测：判断服务器 sshd（-T）当前是否真的支持某维度单算法。
# 对 kex/cipher/mac 用"仅保留该算法"的临时配置做 -t/-T 校验；
# hostkey 需额外校验对应 host key 文件是否存在。
# 返回：0=支持 1=不支持 2=无法探测。
server_algo_supported() {
    local type="$1" algo="$2"
    local tmp out hostkey_file
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 2
    [[ -n "$algo" ]] || return 0

    tmp="$(mktemp /tmp/ssh_algo_single.XXXXXX)" || return 2
    {
        printf '%s\n' '# SSH_ALGO_SINGLE_PROBE'
        printf '%s\n' 'Protocol 2'
        case "$type" in
            kex)    printf '%s\n' "KexAlgorithms $algo" ;;
            cipher) printf '%s\n' "Ciphers $algo" ;;
            mac)    printf '%s\n' "MACs $algo" ;;
            hostkey)
                case "$algo" in
                    ssh-sm2|sm2) hostkey_file="/etc/ssh/ssh_host_sm2_key" ;;
                    ssh-dss) hostkey_file="/etc/ssh/ssh_host_dsa_key" ;;
                    ssh-ed25519) hostkey_file="/etc/ssh/ssh_host_ed25519_key" ;;
                    ssh-ed448) hostkey_file="/etc/ssh/ssh_host_ed448_key" ;;
                    ecdsa-*) hostkey_file="/etc/ssh/ssh_host_ecdsa_key" ;;
                    *) hostkey_file="/etc/ssh/ssh_host_rsa_key" ;;
                esac
                [[ -f "$hostkey_file" ]] || { rm -f "$tmp"; return 1; }
                printf '%s\n' "HostKey $hostkey_file"
                if [[ -n "$SSHD_VER_MAJOR" ]] && { (( SSHD_VER_MAJOR > 6 )) || { (( SSHD_VER_MAJOR == 6 )) && (( SSHD_VER_MINOR >= 5 )); }; }; then
                    printf '%s\n' "HostKeyAlgorithms $algo"
                fi
                ;;
        esac
        cat "$SSHD_CONFIG"
    } > "$tmp"

    if ! "$SSHD_BIN" -t -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"; return 1
    fi
    out="$("$SSHD_BIN" -T -f "$tmp" 2>/dev/null)" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"

    case "$type" in
        kex)
            printf '%s\n' "$out" | awk '$1=="kexalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$algo" ;;
        cipher)
            printf '%s\n' "$out" | awk '$1=="ciphers" {print $2}' | tr ',' '\n' | grep -qxF "$algo" ;;
        mac)
            printf '%s\n' "$out" | awk '$1=="macs" {print $2}' | tr ',' '\n' | grep -qxF "$algo" ;;
        hostkey)
            if printf '%s\n' "$out" | awk '$1=="hostkeyalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$algo"; then
                return 0
            fi
            case "$algo" in
                ssh-rsa|rsa-sha2-256|rsa-sha2-512) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_rsa_key$' ;;
                ssh-dss) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_dsa_key$' ;;
                ssh-ed25519) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ed25519_key$' ;;
                ssh-ed448) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ed448_key$' ;;
                ecdsa-*) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_ecdsa_key$' ;;
                ssh-sm2|sm2) printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -Eq '(^|/)ssh_host_sm2_key$' ;;
                *) return 1 ;;
            esac
            ;;
        *) return 2 ;;
    esac
}

load_dynamic_tests() {
    # 方案 A：先预过滤（Worker 已在 WORKER_*；服务器用 server_algo_supported
    # 逐个 -T 校验），构建"每维度有效候选集"；再按 round-robin 同步推进生成
    # 四元组（kex/cipher/mac/hostkey 同序号），以最长维度为界、循环回绕，
    # 保证每个算法至少出现一次（全覆盖）、组合不重复、数量 = 最长维度长。
    local kex_c=() ciph_c=() mac_c=() hk_c=()
    local algo

    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported kex "$algo"; then kex_c+=("$algo"); fi
    done <<< "$WORKER_KEX"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported cipher "$algo"; then ciph_c+=("$algo"); fi
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported mac "$algo"; then mac_c+=("$algo"); fi
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported hostkey "$algo"; then hk_c+=("$algo"); fi
    done <<< "$WORKER_HOSTKEYS"

    local lk=${#kex_c[@]} lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    local n=$((lk > lc ? lk : (lc > lm ? lc : (lm > lh ? lm : lh))))
    (( n > 0 )) || return 0

    local i k c m h
    for ((i=0; i<n; i++)); do
        # 空维度守卫：某维度候选为空（全部被过滤掉）时，该维度置空，
        # 避免在 len=0 时 ${arr[$((i % len))]} 除零中止脚本。
        (( lk > 0 )) && k="${kex_c[$((i % lk))]}" || k=""
        (( lc > 0 )) && c="${ciph_c[$((i % lc))]}" || c=""
        (( lm > 0 )) && m="${mac_c[$((i % lm))]}" || m=""
        (( lh > 0 )) && h="${hk_c[$((i % lh))]}" || h=""
        # kex / cipher / hostkey 是协商必需维度，三者任一为空则该组合无法协商，跳过。
        [[ -n "$k" && -n "$c" && -n "$h" ]] || continue
        # AEAD cipher 不协商传统 MAC，MAC 置空（置空后再参与去重 key，保证一致）。
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        add_test "组合$((i+1)): kex=$k cipher=$c mac=${m:-NONE} hostkey=$h" \
            "$k" "$c" "$m" "$h" "动态轮转/组合" 2
    done
}

# ============================================================
# 原 test_centos6.sh：实际启用的 test_algo 项
# ============================================================
load_centos6_tests() {
    add_test "blowfish-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "cast128-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "cast128-cbc" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "arcfour + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "arcfour256 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour256" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "arcfour128 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour128" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "rijndael-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "rijndael-cbc@lysator.liu.se" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "3des-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "3des-ctr + hmac-sha1" \
        "diffie-hellman-group14-sha1" "3des-ctr" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "aes256-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes256-cbc" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "aes128-ctr + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes128-ctr" "hmac-sha1" "ssh-rsa" "Cipher" 2
    add_test "aes256-ctr + hmac-md5" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5" "ssh-rsa" "MAC" 2
    add_test "aes256-ctr + hmac-md5-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5-96" "ssh-rsa" "MAC" 2
    add_test "aes256-ctr + hmac-sha1-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-sha1-96" "ssh-rsa" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160" "ssh-rsa" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160-etm" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160-etm@openssh.com" "ssh-rsa" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160@openssh.com" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160@openssh.com" "ssh-rsa" "MAC" 2

    add_test "ssh-dss + 3des-cbc + hmac-md5" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-md5" "ssh-dss" "HostKey" 2
    add_test "ssh-dss + blowfish + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "ssh-dss" "HostKey" 2
}

# ============================================================
# 原 test_centos6_ssh1.sh：实际启用的 5 项
# ============================================================
load_ssh1_tests() {
    add_test "SSH-1: 3des" "" "3des" "" "ssh-rsa1" "SSH-1 Cipher" 1
    add_test "SSH-1: blowfish" "" "blowfish" "" "ssh-rsa1" "SSH-1 Cipher" 1
    add_test "SSH-1: idea" "" "idea" "" "ssh-rsa1" "SSH-1 Cipher" 1
    add_test "SSH-1: arcfour" "" "arcfour" "" "ssh-rsa1" "SSH-1 Cipher" 1
    add_test "SSH-1: des" "" "des" "" "ssh-rsa1" "SSH-1 Cipher" 1
}

# SSH-1 测试双重判定：
#   主条件：当前 sshd 有效配置（sshd -T）的 protocol 是否包含 "1"。
#           （若当前只有 Protocol 2，测试配置改写为 1 后必然被拒，测不了。）
#   附加条件：该 sshd 二进制是否仍支持 SSH-1——用含 Protocol 1 的临时配置做
#            sshd -t 试探；通过才说明"改为 1 协议后真能跑起来"。
# 两个条件都满足才生成 SSH-1 测试项，否则跳过（只测 SSH-2）。

sshd_effective_protocol_has_1() {
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 1
    local out
    out="$("$SSHD_BIN" -T -f "$SSHD_CONFIG" 2>/dev/null | awk '$1 == "protocol" { print $2, $3, $4 }' | tr ' ' '\n' | tr ',' '\n')"
    printf '%s\n' "$out" | grep -qx "1"
}

ssh1_binary_supported() {
    [[ -n "$SSHD_BIN" ]] || return 1
    local tmp
    tmp="$(mktemp /tmp/ssh1probe.XXXXXX 2>/dev/null)" || return 1
    {
        printf '%s\n' '# SSH1_PROBE'
        printf '%s\n' 'Protocol 1'
        printf '%s\n' 'HostKey /etc/ssh/ssh_host_key'
        printf '%s\n' 'PasswordAuthentication yes'
    } > "$tmp"
    if "$SSHD_BIN" -t -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# ============================================================
# 原 test_openssh8.sh：实际启用的 1 项
# ============================================================
load_openssh8_tests() {
    # X448（curve448-sha512）是 OpenSSH 8.x 专项 KEX。同样采用方案 A：
    # 固定 X448 为 kex 锚点，其它维度（cipher/mac/hostkey）用 server_algo_supported
    # 预过滤构建有效候选集，再按 round-robin 全覆盖不重复地生成组合。
    local ciph_c=() mac_c=() hk_c=()
    local algo

    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported cipher "$algo"; then ciph_c+=("$algo"); fi
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported mac "$algo"; then mac_c+=("$algo"); fi
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported hostkey "$algo"; then hk_c+=("$algo"); fi
    done <<< "$WORKER_HOSTKEYS"

    local lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    local n=$((lc > lm ? lc : (lm > lh ? lm : lh)))
    (( n > 0 )) || return 0

    local i c m h
    for ((i=0; i<n; i++)); do
        # 空维度守卫：避免 len=0 时 ${arr[$((i % len))]} 除零中止脚本。
        (( lc > 0 )) && c="${ciph_c[$((i % lc))]}" || c=""
        (( lm > 0 )) && m="${mac_c[$((i % lm))]}" || m=""
        (( lh > 0 )) && h="${hk_c[$((i % lh))]}" || h=""
        # cipher / hostkey 是协商必需维度，任一为空则无法协商，跳过。
        [[ -n "$c" && -n "$h" ]] || continue
        # AEAD cipher 不协商传统 MAC，MAC 置空（置空后再参与去重 key）。
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        add_test "OpenSSH8 X448 组合$((i+1)): kex=curve448-sha512 cipher=$c mac=${m:-NONE} hostkey=$h" \
            "curve448-sha512" "$c" "$m" "$h" "OpenSSH8/X448" 2
    done
}

# ============================================================
# openEuler 国密算法测试
# ============================================================
load_openeuler_tests() {
    # 国密测试策略（与 load_dynamic_tests 相同的方案 A）：
    #   ① 全链路保底：SM2 + SM4 + SM3 + 国密 KEX 完整四要素组合必测。
    #   ② 对 WORKER_* 各维度用 server_algo_supported 逐个 -T 预过滤，
    #      构建"国密有效候选集"。
    #   ③ 以国密算法为锚点（sm2-sm3 / sm4-ctr / hmac-sm3 / ssh-sm2），
    #      按 round-robin 同步推进生成四元组，全覆盖、不重复、数量=最长维。
    add_test "国密全链路: sm2-sm3 + sm4-ctr + hmac-sm3 + ssh-sm2" \
        "sm2-sm3" "sm4-ctr" "hmac-sm3" "ssh-sm2" "国密/全链路" 2

    local kex_c=() ciph_c=() mac_c=() hk_c=()
    local algo

    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported kex "$algo"; then kex_c+=("$algo"); fi
    done <<< "$WORKER_KEX"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported cipher "$algo"; then ciph_c+=("$algo"); fi
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported mac "$algo"; then mac_c+=("$algo"); fi
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        if server_algo_supported hostkey "$algo"; then hk_c+=("$algo"); fi
    done <<< "$WORKER_HOSTKEYS"

    local lk=${#kex_c[@]} lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    local n=$((lk > lc ? lk : (lc > lm ? lc : (lm > lh ? lm : lh))))
    (( n > 0 )) || return 0

    local i k c m h
    for ((i=0; i<n; i++)); do
        # 空维度守卫：避免 len=0 时 ${arr[$((i % len))]} 除零中止脚本。
        (( lk > 0 )) && k="${kex_c[$((i % lk))]}" || k=""
        (( lc > 0 )) && c="${ciph_c[$((i % lc))]}" || c=""
        (( lm > 0 )) && m="${mac_c[$((i % lm))]}" || m=""
        (( lh > 0 )) && h="${hk_c[$((i % lh))]}" || h=""
        # kex / cipher / hostkey 是协商必需维度，三者任一为空则无法协商，跳过。
        [[ -n "$k" && -n "$c" && -n "$h" ]] || continue
        # AEAD cipher 不协商传统 MAC，MAC 置空（置空后再参与去重 key，保证一致）。
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        add_test "国密组合$((i+1)): kex=$k cipher=$c mac=${m:-NONE} hostkey=$h" \
            "$k" "$c" "$m" "$h" "国密/轮转" 2
    done
}

: > "$LOG_FILE"
: > "$ENV_FILE"

if ! detect_env; then
    if $LIST_ONLY; then
        PROFILE="unknown"
    else
        echo "=================================================="
        echo " 环境识别失败：不执行测试，正常退出，不改动任何系统配置。"
        echo "=================================================="
        echo " 系统: ${OS_PRETTY}"
        echo " OpenSSH 客户端: ${SSH_VERSION_STR:-未知}"
        echo " OpenSSH 版本号: ${SSH_VER:-无法解析}"
        echo " init 系统: ${INIT}"
        echo ""
        echo " 本脚本目前只覆盖以下四种画像："
        echo "   1. centos6   OpenSSH < 6.x + SysV/service init（如 CentOS 6.10 / OpenSSH 5.3）"
        echo "   2. openssh8  OpenSSH 8.x + systemd（如 AlmaLinux/Rocky 9、Ubuntu 22.04）"
        echo "   3. modern    OpenSSH >= 9.x + systemd（如 AlmaLinux 10）"
        echo "   4. openeuler openEuler 系统（国密算法测试）"
        echo " 当前环境不在以上范围内，或缺少 systemctl/service 等服务管理"
        echo " 命令，说明这不是本脚本设计要测试的算法协商场景。"
        echo "=================================================="
        exit 0
    fi
fi

load_default_effective_algorithms >/dev/null 2>&1 || true
# crypto policy 放松须在动态探测/组合过滤之前执行（否则被 DEFAULT/FUTURE 屏蔽
# 的算法会被 server_algo_supported 提前过滤掉）；prepare_crypto_policy 幂等。
prepare_crypto_policy
load_worker_algorithms

case "$PROFILE" in
    modern)
        load_dynamic_tests
        ;;
    centos6)
        # SSH-1 探测（ssh1_binary_supported）需要 /etc/ssh/ssh_host_key 存在，
        # 但 prepare_host_keys() 在 load_centos6_tests() 之后才执行。
        # 因此先确保 rsa1 host key 存在，使探测配置的 HostKey 指向有效文件。
        if [[ ! -f /etc/ssh/ssh_host_key ]] && ! $LIST_ONLY; then
            if ssh-keygen -q -t rsa1 -f /etc/ssh/ssh_host_key -N "" >/dev/null 2>&1; then
                GENERATED_HOST_KEYS+=("/etc/ssh/ssh_host_key")
                env_log "SSH-1 探测前预生成 HostKey: /etc/ssh/ssh_host_key"
            fi
        fi
        load_centos6_tests
        # SSH-1 双重判定：当前有效配置 protocol 含 1（主）且 sshd 二进制仍支持
        # SSH-1（附加）时才生成 SSH-1 测试项；否则只测 SSH-2。
        if sshd_effective_protocol_has_1 && ssh1_binary_supported; then
            load_ssh1_tests
        else
            log "跳过 SSH-1 测试：当前 sshd 有效配置不含 Protocol 1，或该二进制不支持 SSH-1；仅测 SSH-2。"
        fi
        ;;
    openssh8)
        load_dynamic_tests
        load_openssh8_tests
        ;;
    openeuler)
        load_openeuler_tests
        load_dynamic_tests
        ;;
    *)
        ;;
esac

if $LIST_ONLY; then
    echo "========================================"
    echo "统一 SSH 算法协商测试项"
    echo "环境：${OS_PRETTY}"
    echo "OpenSSH：${SSH_VERSION_STR:-unknown}"
    echo "Profile：${PROFILE}"
    echo "========================================"
    echo "  列说明：default_supported=当前默认配置(sshd -T)是否已启用该算法"
    echo "           （no 表示默认未启用但能力测试仍入选；n/a 用于 SSH-1）"
    echo "========================================"
    i=0
    for d in "${DESCS[@]}"; do
        i=$((i + 1))
        printf '%3d. %-45s [default=%s]\n' "$i" "$d" "${DEFAULT_FLAGS[$((i - 1))]:-n/a}"
    done
    echo "========================================"
    exit 0
fi

acquire_lock() {
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        # 检查锁中的 PID 是否仍在运行；若已死则清理陈旧锁后重试
        local stale_pid=""
        [[ -f "$LOCK_DIR/pid" ]] && stale_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
        if [[ -n "$stale_pid" ]] && ! kill -0 "$stale_pid" 2>/dev/null; then
            rm -rf "$LOCK_DIR" 2>/dev/null || true
            if mkdir "$LOCK_DIR" 2>/dev/null; then
                printf '%s\n' "$$" > "$LOCK_DIR/pid"
                printf '%s\n' "$TS" > "$LOCK_DIR/start"
                LOCK_ACQUIRED=true
                return 0
            fi
        fi
        echo "错误：已有另一个 SSH 算法测试实例正在运行：$LOCK_DIR" >&2
        return 1
    fi
    printf '%s\n' "$$" > "$LOCK_DIR/pid"
    printf '%s\n' "$TS" > "$LOCK_DIR/start"
    LOCK_ACQUIRED=true
}

release_lock() {
    if $LOCK_ACQUIRED; then
        rm -f "$LOCK_DIR/pid" "$LOCK_DIR/start"
        rmdir "$LOCK_DIR" 2>/dev/null || true
        LOCK_ACQUIRED=false
    fi
}

env_log "SSH 算法协商测试 - 环境/执行信息"
env_log "开始时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
env_log "当前目录: $BASE_DIR"
env_log "系统: $OS_PRETTY"
env_log "OS_ID: $OS_ID"
env_log "OS_VERSION_ID: $OS_VERSION_ID"
env_log "SSH 客户端版本: $SSH_VERSION_STR"
env_log "SSHD 版本: $SSHD_VER"
env_log "SSHD 路径: ${SSHD_BIN:-未找到}"
env_log "SSHD 主版本: ${SSHD_VER_MAJOR:-unknown}"
env_log "SSH 主版本: ${SSH_VER:-unknown}"
env_log "服务: $SERVICE"
env_log "初始化系统: $INIT"
env_log "测试端口: $PORT"
env_log "测试模式: $($AUTO && echo auto || echo manual)"
env_log "筛选: ${ONLY_FILTER:-全部}"
env_log "Profile: $PROFILE"
env_log "结果格式: $RESULT_FORMAT"
env_log "Worker 算法基线: $WORKER_ALGORITHM_FILE"
for command_name in ssh sshd ssh-keygen awk grep sed tr cut head tail stat mktemp date; do
    env_log "命令 ${command_name}: $(need_cmd "$command_name" && echo available || echo missing)"
done
env_log "命令 systemctl: $(need_cmd systemctl && echo available || echo missing)"
env_log "命令 service: $(need_cmd service && echo available || echo missing)"
env_log "命令 journalctl: $(need_cmd journalctl && echo available || echo missing)"
env_log "命令 crontab: $(need_cmd crontab && echo available || echo missing)"
env_log "服务管理选择: INIT=$INIT SERVICE=$SERVICE"

if load_default_effective_algorithms; then
    env_log "默认 sshd -T kexalgorithms: ${DEFAULT_KEX//$'\n'/,}"
    env_log "默认 sshd -T ciphers: ${DEFAULT_CIPHER//$'\n'/,}"
    env_log "默认 sshd -T macs: ${DEFAULT_MAC//$'\n'/,}"
    env_log "默认 sshd -T hostkey: ${DEFAULT_HOSTKEY//$'\n'/,}"
    env_log "默认 sshd -T hostkeyalgorithms: ${DEFAULT_HOSTKEY_ALGORITHMS//$'\n'/,}"
else
    env_log "WARNING：无法读取默认 sshd -T 有效配置"
fi

# ============================================================
# 初始服务状态 / crypto-policies 状态记录
# ============================================================
record_initial_state() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        if systemctl is-active --quiet "$SERVICE"; then
            INITIAL_SERVICE_ACTIVE=true
        else
            INITIAL_SERVICE_ACTIVE=false
        fi
        INITIAL_SERVICE_KNOWN=true
    elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        if service "$SERVICE" status >/dev/null 2>&1; then
            INITIAL_SERVICE_ACTIVE=true
        else
            INITIAL_SERVICE_ACTIVE=false
        fi
        INITIAL_SERVICE_KNOWN=true
    fi

    if command -v update-crypto-policies >/dev/null 2>&1; then
        INITIAL_CRYPTO_POLICY="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
            env_log "初始 crypto-policy: $INITIAL_CRYPTO_POLICY"
        fi
    fi
}

backup_config() {
    [[ -f "$SSHD_CONFIG" ]] || die "配置文件不存在：$SSHD_CONFIG"
    mkdir -p -m 700 "$STATE_DIR" || die "无法创建状态目录：$STATE_DIR"
    STATE_DIR_CREATED=true
    cp -a "$SSHD_CONFIG" "$BACKUP_FILE" || die "无法备份 $SSHD_CONFIG"
    chmod 600 "$BACKUP_FILE" || true
    env_log "配置备份: $BACKUP_FILE"
    env_log "状态目录: $STATE_DIR"
}

verify_restored_state() {
    local cfg_ok=true svc_ok=true crypto_ok=true temp_ok=true

    if [[ -n "$SSHD_BIN" ]]; then
        if "$SSHD_BIN" -t -f "$SSHD_CONFIG" >/dev/null 2>&1; then
            log "[恢复验证] sshd_config: PASS"
        else
            cfg_ok=false
            log "[恢复验证] sshd_config: FAIL（sshd -t 失败）"
        fi
    else
        cfg_ok=false
        log "[恢复验证] sshd_config: UNKNOWN（未找到 sshd）"
    fi

    if $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            if service_is_up; then
                log "[恢复验证] service state: PASS（运行）"
            else
                svc_ok=false
                log "[恢复验证] service state: FAIL（应运行但未运行）"
            fi
        else
            if service_is_up; then
                svc_ok=false
                log "[恢复验证] service state: FAIL（应停止但仍运行）"
            else
                log "[恢复验证] service state: PASS（停止）"
            fi
        fi
    else
        log "[恢复验证] service state: UNKNOWN（测试前服务状态未知）"
    fi

    if $CRYPTO_POLICY_CHANGED && command -v update-crypto-policies >/dev/null 2>&1 && [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
        local final_crypto
        final_crypto="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ "$final_crypto" == "$INITIAL_CRYPTO_POLICY" ]]; then
            log "[恢复验证] crypto-policy: PASS ($final_crypto)"
        else
            crypto_ok=false
            log "[恢复验证] crypto-policy: FAIL（当前='$final_crypto'，期望='$INITIAL_CRYPTO_POLICY'）"
        fi
    fi

    if find /tmp -maxdepth 1 -type f \( -name 'algo_client.$$.*' -o -name 'algo_sshd_t.$$.*' \) -print -quit 2>/dev/null | grep -q .; then
        temp_ok=false
        log "[恢复验证] temporary files: FAIL（发现测试临时文件）"
    else
        log "[恢复验证] temporary files: PASS（CLEAN）"
    fi

    if $cfg_ok && $svc_ok && $crypto_ok && $temp_ok; then
        log "[恢复验证] 总体：PASS"
    else
        log "[恢复验证] 总体：FAIL，请检查上述恢复验证日志"
    fi
}

restore_all() {
    $RESTORED && return
    RESTORED=true

    printf '\n' | tee -a "$LOG_FILE"
    log "[恢复] 开始恢复配置、服务状态和临时文件..."

    if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    CLIENT_PID=""

    # 自动模式临时公钥只删除本脚本自己添加的那一行，不触碰用户原有 authorized_keys。
    if $AUTO_AUTH_KEY_ADDED && [[ -f /root/.ssh/authorized_keys ]]; then
        local auth_tmp
        auth_tmp="$(mktemp /root/.ssh/authorized_keys.restore.XXXXXX 2>/dev/null || true)"
        if [[ -n "$auth_tmp" ]]; then
            grep -vF "$AUTO_MARKER" /root/.ssh/authorized_keys > "$auth_tmp" 2>/dev/null || true
            chmod 600 "$auth_tmp"
            mv -f "$auth_tmp" /root/.ssh/authorized_keys
            log "[恢复] 自动模式临时公钥已移除"
        fi
    fi
    rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"

    # 恢复测试前的 sshd_config；整个恢复过程使用同目录临时文件 + mv，避免半写状态。
    # 若测试期间管理员/配置管理工具已修改 sshd_config（不含测试 marker），
    # 不覆盖其修改，记录警告后保留现状。
    if [[ -f "$BACKUP_FILE" ]]; then
        if grep -qF 'ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT' "$SSHD_CONFIG" 2>/dev/null; then
            local restore_tmp
            restore_tmp="$(mktemp "${SSHD_CONFIG}.restore.XXXXXX")"
            if cp -a "$BACKUP_FILE" "$restore_tmp" && mv -f "$restore_tmp" "$SSHD_CONFIG"; then
                log "[恢复] sshd_config 已恢复"
            else
                log "[恢复] ERROR：sshd_config 恢复失败"
                RESTORE_FAILED=true
                rm -f "$restore_tmp"
            fi
        else
            log "[恢复] WARNING：sshd_config 已被外部修改（不含测试 marker），跳过恢复以避免覆盖外部修改"
        fi
    fi

    # 删除本次运行期间新生成、原本不存在的 host key。
    local hk
    for hk in "${GENERATED_HOST_KEYS[@]}"; do
        rm -f "$hk" "${hk}.pub"
        log "[恢复] 删除本次生成的 HostKey：$hk"
    done

    if $CRYPTO_POLICY_CHANGED && command -v update-crypto-policies >/dev/null 2>&1 && [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
        local current_crypto=""
        current_crypto="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ "$current_crypto" == "LEGACY" ]]; then
            if update-crypto-policies --set "$INITIAL_CRYPTO_POLICY" >/dev/null 2>&1; then
                log "[恢复] crypto-policy 已恢复：$INITIAL_CRYPTO_POLICY"
            else
                log "[恢复] ERROR：crypto-policy 恢复失败"
            fi
        else
            log "[恢复] WARNING：crypto-policy 当前为 '$current_crypto'，不是本脚本设置的 LEGACY；跳过恢复，避免覆盖其他进程的修改"
        fi
    fi

    rm -f /tmp/algo_client.$$.* /tmp/algo_sshd_t.$$.*
    # 清理本脚本在 /etc/ssh/ 下创建的测试临时文件。只删除带 ALGO_TEST
    # marker、确属本流程生成的文件（而非任意 sshd_config.* 通配），
    # 避免误删其它进程/管理员文件；也兼容 kill -9 后由恢复钩子清理。
    if command -v grep >/dev/null 2>&1; then
        grep -lF 'ALGO_TEST_ACTIVE_MARKER' \
            /etc/ssh/sshd_config.?????? /etc/ssh/sshd_config.restore.?????? \
            /etc/ssh/sshd_config.recover.?????? 2>/dev/null | xargs -r rm -f -- 2>/dev/null || true
    fi

    # 恢复测试前服务运行状态；不因为脚本测试过程中重启过就改变原状态。
    if $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            if service_restart; then
                log "[恢复] 服务状态：恢复为测试前运行状态"
            else
                log "[恢复] ERROR：无法恢复 sshd 运行状态"
            fi
        else
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || true
            fi
            log "[恢复] 服务状态：恢复为测试前停止状态"
        fi
    fi

    # 还原本测试覆盖前备份的管理员原文件（RESTORE_HELPER / systemd drop-in 等）。
    local _pair _orig _bakbak
    for _pair in "${PREEXISTING_BACKUPS[@]:-}"; do
        _orig="${_pair%%|*}"
        _bakbak="${_pair#*|}"
        if [[ -n "$_orig" && -f "$_bakbak" ]]; then
            if mv -f "$_bakbak" "$_orig" 2>/dev/null; then
                log "[恢复] 已还原被覆盖路径：$_orig"
            else
                log "[恢复] ERROR：还原 $_orig 失败"
                RESTORE_FAILED=true
            fi
        fi
    done
    PREEXISTING_BACKUPS=()

    # 删除本次运行创建的崩溃自愈钩子和 PID。
    rm -f "$PID_FILE"
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        if [[ -n "$SYSTEMD_DROPIN_FILE" ]]; then rm -f "$SYSTEMD_DROPIN_FILE"; fi
        if [[ -n "$SYSTEMD_DROPIN_DIR" ]]; then rmdir "$SYSTEMD_DROPIN_DIR" 2>/dev/null || true; fi
        rm -f "$RESTORE_HELPER"
        systemctl daemon-reload >/dev/null 2>&1 || true
    elif [[ "$INIT" == "sysv/service" ]] && command -v crontab >/dev/null 2>&1; then
        local cron_now cron_tmp
        cron_now="$(crontab -l 2>/dev/null || true)"
        cron_tmp="$(mktemp /tmp/ssh-algo-unified-cron-clean.XXXXXX 2>/dev/null || true)"
        if [[ -n "$cron_tmp" ]]; then
            printf '%s\n' "$cron_now" | grep -vF "$CRON_TAG" > "$cron_tmp" || true
            crontab "$cron_tmp" 2>/dev/null || true
            rm -f "$cron_tmp"
        fi
        rm -f "$RESTORE_HELPER"
    fi

    verify_restored_state

    if $STATE_DIR_CREATED; then
        rm -rf -- "$STATE_DIR"
        STATE_DIR_CREATED=false
    fi
    release_lock
    log "[恢复] 临时文件和测试客户端已清理"
    if $RESTORE_FAILED; then
        log "[恢复] ERROR：存在恢复失败项；为避免 sshd 停留在测试配置上，脚本以非零码退出。"
        exit 1
    fi
    log "[恢复] 完成"
}

backup_preexisting() {
    # 若目标路径已存在且不是本测试之前创建的（不含 ALGO_TEST marker），
    # 备份到 STATE_DIR，恢复时通过 PREEXISTING_BACKUPS 还原，避免覆盖管理员原有文件。
    local f="$1"
    [[ -n "$f" && -e "$f" ]] || return 0
    if grep -qF 'ALGO_TEST' "$f" 2>/dev/null; then
        return 0   # 是本测试的残留，直接可覆盖/删除
    fi
    local bak="$STATE_DIR/preexisting_$(basename "$f").$$"
    if cp -a "$f" "$bak" 2>/dev/null; then
        PREEXISTING_BACKUPS+=("$f|$bak")
        env_log "备份被覆盖路径（恢复时还原）: $f -> $bak"
    fi
}

install_recovery() {
    # PID 文件写入 2 字段：PID 和进程启动时间（/proc/[pid]/stat 第 22 字段），
    # 供崩溃自愈 helper 比对，避免 PID 被其它进程复用后误判“原测试仍在运行”。
    echo "$$ $(awk '{print $22}' /proc/$$/stat 2>/dev/null || echo 0)" > "$PID_FILE" || die "无法创建 PID 文件：$PID_FILE"

    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        SYSTEMD_DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
        SYSTEMD_DROPIN_FILE="${SYSTEMD_DROPIN_DIR}/ssh-algo-unified.conf"

        local helper_tmp dropin_tmp
        mkdir -p "$(dirname "$RESTORE_HELPER")"
        helper_tmp="$(mktemp "${RESTORE_HELPER}.XXXXXX")" || die "无法创建恢复脚本"
        cat > "$helper_tmp" <<EOF
#!/bin/bash
set -u
CONFIG="$SSHD_CONFIG"
BACKUP="$BACKUP_FILE"
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
PIDFILE="$PID_FILE"
SERVICE="$SERVICE"
DROPIN="$SYSTEMD_DROPIN_FILE"
DROPIN_DIR="$SYSTEMD_DROPIN_DIR"
if [[ -f "\$BACKUP" ]] && grep -qF "\$MARKER" "\$CONFIG" 2>/dev/null; then
    restore=false
    if [[ ! -f "\$PIDFILE" ]]; then
        restore=true
    else
        pid="\$(cat "\$PIDFILE" 2>/dev/null || true)"
        # PID 文件为 "PID STARTTIME" 两字段；比对 /proc/[pid]/stat 第 22 字段，
        # 防止 PID 被其它进程复用后误判“原测试仍在运行”。
        if [[ -z "\$pid" ]]; then restore=true
        else
            pid_start="\$(printf '%s' "\$pid" | awk '{print \$2}')"
            pid_num="\$(printf '%s' "\$pid" | awk '{print \$1}')"
            if [[ -z "\$pid_num" ]]; then restore=true
            elif ! kill -0 "\$pid_num" 2>/dev/null; then restore=true
            else
                cur_start="\$(awk '{print \$22}' "/proc/\$pid_num/stat" 2>/dev/null || echo 0)"
                if [[ -z "\$pid_start" || "\$pid_start" != "\$cur_start" ]]; then restore=true; fi
            fi
        fi
    fi
    if \$restore; then
        t="\$(mktemp "\${CONFIG}.recover.XXXXXX")"
        if cp -a "\$BACKUP" "\$t"; then
            mv -f "\$t" "\$CONFIG"
            logger -t ssh-algo-unified "检测到异常中止测试配置，已恢复备份" 2>/dev/null || true
            rm -f "\$PIDFILE" "\$BACKUP" "\$DROPIN"
            rmdir "\$DROPIN_DIR" 2>/dev/null || true
            # 清理可能残留的锁目录，避免后续运行报"已有实例正在运行"
            rm -rf /var/run/ssh-algo-unified.lock 2>/dev/null || true
            # 清理 /etc/ssh/ 下的测试临时文件（仅删带 ALGO_TEST marker 的）
            grep -lF 'ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT' \
                /etc/ssh/sshd_config.?????? /etc/ssh/sshd_config.restore.?????? \
                /etc/ssh/sshd_config.recover.?????? 2>/dev/null | xargs -r rm -f -- 2>/dev/null || true
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl restart "\$SERVICE" >/dev/null 2>&1 || true
        else
            rm -f "\$t"
        fi
    fi
fi
exit 0
EOF
        chmod 755 "$helper_tmp"
        backup_preexisting "$RESTORE_HELPER"
        mv -f "$helper_tmp" "$RESTORE_HELPER"
        mkdir -p "$SYSTEMD_DROPIN_DIR"
        backup_preexisting "$SYSTEMD_DROPIN_FILE"
        dropin_tmp="$(mktemp "${SYSTEMD_DROPIN_FILE}.XXXXXX")" || die "无法创建 systemd recovery drop-in"
        cat > "$dropin_tmp" <<EOF
# SSH algorithm unified test temporary recovery hook
[Service]
ExecStartPre=$RESTORE_HELPER
EOF
        if [[ -f /etc/crypto-policies/back-ends/opensslcnf.config ]]; then
            printf '%s\n' 'Environment=OPENSSL_CONF=/etc/crypto-policies/back-ends/opensslcnf.config' >> "$dropin_tmp"
        fi
        mv -f "$dropin_tmp" "$SYSTEMD_DROPIN_FILE"
        systemctl daemon-reload >/dev/null 2>&1 || true
        RECOVERY_INSTALLED=true

    elif [[ "$INIT" == "sysv/service" && "$SERVICE" != "unknown" ]] && command -v crontab >/dev/null 2>&1; then
        local cron_tmp current
        current="$(crontab -l 2>/dev/null || true)"
        cron_tmp="$(mktemp /tmp/ssh-algo-unified-cron.XXXXXX)"
        printf '%s\n' "$current" | grep -vF "$CRON_TAG" > "$cron_tmp" || true
        printf '@reboot %s %s\n' "$RESTORE_HELPER" "$CRON_TAG" >> "$cron_tmp"
        cat > "${RESTORE_HELPER}.tmp" <<EOF
#!/bin/bash
set -u
CONFIG="$SSHD_CONFIG"
BACKUP="$BACKUP_FILE"
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
SERVICE="$SERVICE"
if [[ -f "\$BACKUP" ]] && grep -qF "\$MARKER" "\$CONFIG" 2>/dev/null; then
    t="\$(mktemp "\${CONFIG}.recover.XXXXXX")"
    if cp -a "\$BACKUP" "\$t"; then
        mv -f "\$t" "\$CONFIG"
        service "\$SERVICE" restart >/dev/null 2>&1 || true
    else
        rm -f "\$t"
    fi
fi
exit 0
EOF
        chmod 755 "${RESTORE_HELPER}.tmp"
        backup_preexisting "$RESTORE_HELPER"
        mv -f "${RESTORE_HELPER}.tmp" "$RESTORE_HELPER"
        crontab "$cron_tmp" 2>/dev/null || true
        rm -f "$cron_tmp"
        RECOVERY_INSTALLED=true
    fi
}

trap 'restore_all; exit 130' INT
trap 'restore_all; exit 143' TERM
trap restore_all EXIT

acquire_lock || exit 1

record_initial_state
backup_config
install_recovery

prepare_crypto_policy() {
    # 保存当前 crypto-policy 并按需放松：modern/openssh8 画像下切换到
    # LEGACY，使 sshd -T 探测能看到被 DEFAULT/FUTURE 策略屏蔽的算法；
    # 测试结束后由 restore_all 恢复原始策略。
    detect_crypto_policy_tool
    if [[ -n "$CRYPTO_POLICY_TOOL" ]]; then
        INITIAL_CRYPTO_POLICY="$("$CRYPTO_POLICY_TOOL" --show 2>/dev/null || true)"
        [[ -n "$INITIAL_CRYPTO_POLICY" ]] && env_log "crypto-policy（原始）: $INITIAL_CRYPTO_POLICY"
    fi
    crypto_policy_relax_for_test
}

prepare_host_keys() {
    # 仅在原文件不存在时生成；成功后立即登记。生成失败/半成品全部清理，
    # 避免异常退出留下不完整的系统 HostKey。
    local key path generated_ok
    local key_list="rsa ed25519 ecdsa dsa"
    [[ "$PROFILE" == "centos6" ]] && key_list+=" rsa1"
    [[ "$PROFILE" == "openeuler" ]] && key_list+=" sm2"
    for key in $key_list; do
        case "$key" in
            rsa) path="/etc/ssh/ssh_host_rsa_key" ;;
            ed25519) path="/etc/ssh/ssh_host_ed25519_key" ;;
            ecdsa) path="/etc/ssh/ssh_host_ecdsa_key" ;;
            dsa) path="/etc/ssh/ssh_host_dsa_key" ;;
            rsa1) path="/etc/ssh/ssh_host_key" ;;
            sm2) path="/etc/ssh/ssh_host_sm2_key" ;;
        esac
        [[ -f "$path" ]] && continue

        generated_ok=false
        case "$key" in
            rsa) ssh-keygen -q -t rsa -b 4096 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            ed25519) ssh-keygen -q -t ed25519 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            ecdsa) ssh-keygen -q -t ecdsa -b 521 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            dsa) ssh-keygen -q -t dsa -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            rsa1) ssh-keygen -q -t rsa1 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            sm2) ssh-keygen -q -t sm2 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
        esac

        if $generated_ok && [[ -f "$path" ]]; then
            GENERATED_HOST_KEYS+=("$path")
            env_log "本次测试新生成 HostKey: $path"
        else
            rm -f "$path" "${path}.pub"
            env_log "WARNING：HostKey 生成失败，已清理半成品：$path"
        fi
    done
}


prepare_auto_key() {
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"
    # CentOS 6 的 OpenSSH 5.3 不支持 ed25519，需回退到 rsa。
    if ! ssh-keygen -t ed25519 -f "$AUTO_KEY" -N "" -q 2>/dev/null; then
        ssh-keygen -t rsa -b 2048 -f "$AUTO_KEY" -N "" -q || return 1
    fi

    touch /root/.ssh/authorized_keys
    local auth_tmp
    auth_tmp="$(mktemp /root/.ssh/authorized_keys.prepare.XXXXXX)" || return 1
    # 同一工具的旧 marker 视为上次异常残留，先移除，再加入本次临时公钥。
    grep -vF "$AUTO_MARKER" /root/.ssh/authorized_keys > "$auth_tmp" 2>/dev/null || true
    printf '%s %s\n' "$(cat "$AUTO_PUB")" "$AUTO_MARKER" >> "$auth_tmp"
    # 仅当实际存在 SSH-1 测试项时才生成 RSA1 密钥，避免因 SSH-1 测试
    # 被跳过时仍因 rsa1 生成失败而 die 退出。
    local has_ssh1=false
    local _p
    for _p in "${PROTOCOLS[@]}"; do
        [[ "$_p" == "1" ]] && { has_ssh1=true; break; }
    done
    if [[ "$PROFILE" == "centos6" ]] && $has_ssh1; then
        if ! ssh-keygen -t rsa1 -b 1024 -f "$AUTO_SSH1_KEY" -N "" -q 2>/dev/null ||
           [[ ! -s "$AUTO_SSH1_PUB" ]]; then
            rm -f "$auth_tmp" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"
            return 1
        fi
        printf '%s %s\n' "$(cat "$AUTO_SSH1_PUB")" "$AUTO_MARKER" >> "$auth_tmp"
    fi
    chmod 600 "$auth_tmp"
    mv -f "$auth_tmp" /root/.ssh/authorized_keys
    AUTO_AUTH_KEY_ADDED=true
}

prepare_crypto_policy
prepare_host_keys

if $AUTO; then
    prepare_auto_key || die "无法准备自动模式临时认证密钥"
fi

if [[ "$RESULT_FORMAT" == "csv" ]]; then
    printf '%s\n' \
        'index,description,group,protocol,fixed_kex,fixed_cipher,fixed_mac,fixed_hostkey,negotiated_kex,negotiated_cipher,negotiated_mac,negotiated_hostkey,result,client_result,default_supported,reason' \
        > "$CSV_FILE"
else
    printf '[\n' > "$JSON_FILE"
fi

write_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" default_supported="${16}" reason="${17}"

    # AEAD 加密（chacha20-poly1305 / AES-GCM）不使用传统 MAC。测试组合里
    # 的 MAC 只是占位控制变量；报告层明确标注为 AEAD/N，避免误导为真实协商 MAC。
    local fm_report="$fm"
    case "$fc" in
        chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
            fm_report="AEAD/N (no traditional MAC)"
            ;;
    esac

    # 合并协商结果(nr)与认证结果(ar)为单一总体结果，供报告展示：
    #   - 协商非 PASS（FAIL/UNKNOWN/SKIP）→ 直接取 nr，整体不成立
    #   - 协商 PASS + 认证 PASS → PASS
    #   - 协商 PASS + 认证 FAIL → AUTH_FAIL（协商成功但登录失败）
    #   - 协商 PASS + 认证 UNKNOWN/其它 → PASS（协商为主，认证未知不判失败）
    local overall="$nr"
    case "$nr" in
        PASS)
            case "$ar" in
                PASS) overall="PASS" ;;
                FAIL) overall="AUTH_FAIL" ;;
                *) overall="PASS" ;;
            esac
            ;;
    esac

    if [[ "$RESULT_FORMAT" == "csv" ]]; then
        {
            csv_escape "$idx"; printf ','
            csv_escape "$desc"; printf ','
            csv_escape "$group"; printf ','
            csv_escape "$proto"; printf ','
            csv_escape "$fk"; printf ','
            csv_escape "$fc"; printf ','
            csv_escape "$fm_report"; printf ','
            csv_escape "$fh"; printf ','
            csv_escape "$nk"; printf ','
            csv_escape "$nc"; printf ','
            csv_escape "$nm"; printf ','
            csv_escape "$nh"; printf ','
            csv_escape "$overall"; printf ','
            csv_escape "$cr"; printf ','
            csv_escape "$default_supported"; printf ','
            csv_escape "$reason"; printf '\n'
        } >> "$CSV_FILE"
    else
        if (( RUN_INDEX > 1 )); then
            printf ',\n' >> "$JSON_FILE"
        fi
        printf '  {"index":%s,"description":"%s","group":"%s","protocol":"%s","fixed":{"kex":"%s","cipher":"%s","mac":"%s","hostkey":"%s"},"negotiated":{"kex":"%s","cipher":"%s","mac":"%s","hostkey":"%s"},"result":"%s","client_result":"%s","default_supported":"%s","reason":"%s"}' \
            "$idx" "$(json_escape "$desc")" "$(json_escape "$group")" "$(json_escape "$proto")" \
            "$(json_escape "$fk")" "$(json_escape "$fc")" "$(json_escape "$fm_report")" "$(json_escape "$fh")" \
            "$(json_escape "$nk")" "$(json_escape "$nc")" "$(json_escape "$nm")" "$(json_escape "$nh")" \
            "$(json_escape "$overall")" "$(json_escape "$cr")" "$(json_escape "$default_supported")" "$(json_escape "$reason")" \
            >> "$JSON_FILE"
    fi
}

should_run() {
    local idx="$1"
    local desc="$2"

    [[ -z "$ONLY_FILTER" ]] && return 0

    if [[ "$ONLY_FILTER" =~ ^[0-9]+$ ]]; then
        [[ "$((10#$idx))" == "$((10#$ONLY_FILTER))" ]]
        return
    fi

    shopt -s nocasematch
    [[ "$desc" == *"$ONLY_FILTER"* ]]
    local r=$?
    shopt -u nocasematch
    return "$r"
}

service_restart() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        systemctl restart "$SERVICE" >/dev/null 2>&1
        return $?
    fi

    if command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        service "$SERVICE" restart >/dev/null 2>&1
        return $?
    fi

    return 1
}

wait_service_ready() {
    # 部分算法（如 8192-bit DH group18-sha512）sshd 启动会明显变慢，
    # 固定 sleep 3 秒可能造成误判为"启动失败"。这里改成最多等 60 秒的
    # 轮询；systemd 环境下如果服务触发了 start-limit-hit（短时间内重启
    # 次数过多被熔断），主动 reset-failed 后重试一次而不是干等到超时。
    local max_wait=60
    local i
    local retried=false
    for i in $(seq 1 "$max_wait"); do
        if service_is_up; then
            return 0
        fi
        if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]] && ! $retried; then
            if systemctl is-failed --quiet "$SERVICE" 2>/dev/null; then
                retried=true
                systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
                service_restart >/dev/null 2>&1 || true
            fi
        fi
        sleep 1
    done
    service_is_up
}

service_is_up() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        systemctl is-active --quiet "$SERVICE"
        return $?
    fi

    if command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        service "$SERVICE" status >/dev/null 2>&1
        return $?
    fi

    return 1
}

detect_log_file() {
    if [[ -f /var/log/secure ]]; then
        printf '%s\n' /var/log/secure
        return
    fi
    if [[ -f /var/log/auth.log ]]; then
        printf '%s\n' /var/log/auth.log
        return
    fi
    if [[ "$INIT" == "systemd" ]] && command -v journalctl >/dev/null 2>&1; then
        printf '%s\n' "JOURNAL:$SERVICE"
        return
    fi
    printf '%s\n' ""
}

file_size() {
    # 跨平台获取文件字节数：
    #   GNU/Linux:  stat -c %s
    #   BSD/macOS:  stat -f %z
    #   兜底:       wc -c
    local f="$1"
    [[ -f "$f" ]] || { printf '0\n'; return 0; }
    if stat -c %s "$f" >/dev/null 2>&1; then
        stat -c %s "$f" 2>/dev/null
    elif stat -f %z "$f" >/dev/null 2>&1; then
        stat -f %z "$f" 2>/dev/null
    else
        wc -c < "$f" 2>/dev/null | tr -d ' '
    fi
}

read_log_delta() {
    local file="$1" size="$2"
    if [[ "$file" == JOURNAL:* ]]; then
        local unit="${file#JOURNAL:}"
        journalctl -u "${unit}.service" --since "$TEST_START_TIME" --no-pager -o short-iso 2>/dev/null || true
        return 0
    fi
    [[ -f "$file" ]] || return 0
    local cur
    cur="$(file_size "$file")"
    if (( cur >= size )); then
        tail -c +"$((size + 1))" "$file" 2>/dev/null || true
    else
        cat "$file" 2>/dev/null || true
    fi
}

wait_for_server_log() {
    local file="$1" size="$2" attempt delta
    for attempt in 1 2 3 4 5; do
        delta="$(read_log_delta "$file" "$size")"
        if [[ -n "$delta" ]]; then
            printf '%s\n' "$delta"
            return 0
        fi
        sleep 1
    done
    return 0
}

wait_for_manual_client() {
    # 手动模式：客户端（如 CF Worker）在自己的系统中点"连接"才会向本机
    # 发起 SSH 请求，脚本无法预知何时到来，因此不依赖 Enter，而是持续轮询
    # 服务端日志，直到检测到该次连接的协商/握手信号自动继续，或超时。
    local file="$1" size="$2"
    # 默认等待 10 分钟（600 秒），可用 MANUAL_WAIT_MAX 覆盖。
    local max_wait="${MANUAL_WAIT_MAX:-600}"
    local acc="" waited=0
    # 若没有可用的服务端日志文件（detect_log_file 返回空），无从等待与判断，
    # 直接记录告警并返回空，避免每项干等超时。
    if [[ -z "$file" ]]; then
        log "警告：未找到服务端日志文件，无法等待外部客户端连接；本项按当前状态记录。"
        return 0
    fi
    log "等待外部客户端连接（最多 ${max_wait} 秒；客户端发起连接后自动继续，无需手动 Enter）"
    while (( waited < max_wait )); do
        local d cur_size
        d="$(read_log_delta "$file" "$size")"
        if [[ -n "$d" ]]; then
            # 只对本次新增的日志片段判断；把 size 推进到文件当前大小，
            # 避免下一轮重复读同一段而无限累积同内容，或旧连接反复命中。
            if printf '%s\n' "$d" | grep -qiE \
                'kex: |server->client|Offering |Accepted password|Accepted publickey|PAM: authentication|kex_exchange_identification'; then
                acc+="$d"
                log "已检测到外部客户端连接日志，自动进入下一项。"
                printf '%s' "$acc"
                return 0
            fi
            acc+="$d"
        fi
        cur_size="$(file_size "$file")"
        if [[ "$file" != JOURNAL:* && "$cur_size" != "$size" ]]; then
            size="$cur_size"
        fi
        sleep 2
        waited=$((waited + 2))
    done
    log "等待外部客户端连接超时（${max_wait} 秒），本项按当前状态记录并继续。"
    printf '%s' "$acc"
    return 0
}

text_matches() {
    local pattern="$1" text="$2"
    printf '%s\n' "$text" | grep -qiE "$pattern"
}

last_matching_text() {
    local pattern="$1" text="$2"
    printf '%s\n' "$text" | grep -iE "$pattern" | tail -1
}

# 使用 sshd -Q 做“理论能力预检”，使用 sshd -T 做“最终配置预检”。
# 预检只决定 SKIP，不决定 PASS/FAIL；最终结果仍由真实 SSH 协商决定。
SUPPORTED_KEX=""
SUPPORTED_CIPHER=""
SUPPORTED_MAC=""
SUPPORTED_HOSTKEY=""
EFFECTIVE_KEX=""
EFFECTIVE_CIPHER=""
EFFECTIVE_MAC=""
EFFECTIVE_HOSTKEY=""
EFFECTIVE_HOSTKEY_ALGORITHMS=""
load_supported_algorithms() {
    [[ -n "$SSHD_BIN" ]] || return 0

    # OpenSSH 5.3 接受 -Q 但不提供现代版本的算法查询输出；空结果不能
    # 解释为“不支持任何算法”，因此 CentOS 6 不使用该接口做预检。
    if [[ "$PROFILE" != "centos6" ]]; then
        SUPPORTED_KEX="$("$SSHD_BIN" -Q kex 2>/dev/null || true)"
        SUPPORTED_CIPHER="$("$SSHD_BIN" -Q cipher 2>/dev/null || true)"
        SUPPORTED_MAC="$("$SSHD_BIN" -Q mac 2>/dev/null || true)"
        SUPPORTED_HOSTKEY="$("$SSHD_BIN" -Q key 2>/dev/null || true)"
    fi
    env_log "sshd -Q kex: $([[ -n "$SUPPORTED_KEX" ]] && echo available || echo unavailable/not-used)"
    env_log "sshd -Q cipher: $([[ -n "$SUPPORTED_CIPHER" ]] && echo available || echo unavailable/not-used)"
    env_log "sshd -Q mac: $([[ -n "$SUPPORTED_MAC" ]] && echo available || echo unavailable/not-used)"
    env_log "sshd -Q key: $([[ -n "$SUPPORTED_HOSTKEY" ]] && echo available || echo unavailable/not-used)"
}

load_effective_algorithms() {
    local config="$1" output
    EFFECTIVE_KEX=""
    EFFECTIVE_CIPHER=""
    EFFECTIVE_MAC=""
    EFFECTIVE_HOSTKEY=""
    EFFECTIVE_HOSTKEY_ALGORITHMS=""

    [[ -n "$SSHD_BIN" && -f "$config" ]] || return 2
    output="$("$SSHD_BIN" -T -f "$config" 2>/dev/null)" || return 1

    EFFECTIVE_KEX="$(printf '%s\n' "$output" | awk '$1 == "kexalgorithms" { print $2 }' | tr ',' '\n')"
    EFFECTIVE_CIPHER="$(printf '%s\n' "$output" | awk '$1 == "ciphers" { print $2 }' | tr ',' '\n')"
    EFFECTIVE_MAC="$(printf '%s\n' "$output" | awk '$1 == "macs" { print $2 }' | tr ',' '\n')"
    # OpenSSH 5.x 的 -T 输出是 hostkey 文件路径；现代版本也可能输出
    # hostkey 路径，因此统一保留路径，algo_effective_supported 再映射算法名。
    EFFECTIVE_HOSTKEY="$(printf '%s\n' "$output" | awk '$1 == "hostkey" { print $2 }')"
    EFFECTIVE_HOSTKEY_ALGORITHMS="$(printf '%s\n' "$output" | awk '$1 == "hostkeyalgorithms" { print $2 }' | tr \, '\n')"

    env_log "sshd -T -f $config: available"
    return 0
}

algo_effective_supported() {
    local type="$1" algo="$2" list=""
    [[ -n "$algo" ]] || return 0
    case "$type" in
        kex) list="$EFFECTIVE_KEX" ;;
        cipher) list="$EFFECTIVE_CIPHER" ;;
        mac) list="$EFFECTIVE_MAC" ;;
        key)
            # 新版 OpenSSH 直接验证 HostKeyAlgorithms；CentOS 6/OpenSSH 5.3
            # 没有该输出时，退回 hostkey 文件路径映射。
            if [[ -n "$EFFECTIVE_HOSTKEY_ALGORITHMS" ]] && printf '%s\n' "$EFFECTIVE_HOSTKEY_ALGORITHMS" | grep -qxF "$algo"; then
                return 0
            fi
            case "$algo" in
                ssh-rsa|rsa-sha2-256|rsa-sha2-512)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_rsa_key$' && return 0
                    ;;
                ssh-dss)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_dsa_key$' && return 0
                    ;;
                ssh-ed25519)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_ed25519_key$' && return 0
                    ;;
                ssh-ed448)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_ed448_key$' && return 0
                    ;;
                ecdsa-*)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_ecdsa_key$' && return 0
                    ;;
                ssh-sm2|sm2)
                    printf '%s\n' "$EFFECTIVE_HOSTKEY" | grep -Eq '(^|/)ssh_host_sm2_key$' && return 0
                    ;;
                *) return 1 ;;
            esac
            ;;
        *) return 0 ;;
    esac
    printf '%s\n' "$list" | grep -qxF "$algo"
}

make_test_config_from_backup() {
    local proto="$1" idx="$2" desc="$3" kex="$4" cipher="$5" mac="$6" hostkey="$7" ssh1cipher="$8" compression="$9"
    local tmp
    tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")" || return 1

    # 覆盖块放在原配置最前面。OpenSSH 对同一全局选项通常采用首次获得的值，
    # 这样 /etc/ssh/sshd_config.d/*.conf 中已有算法设置不会抢先生效。
    {
        printf '%s\n' '# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT'
        printf '%s\n' "# 测试项: [#${idx}] ${desc}"
        printf '%s\n' "Port ${PORT}"
        if $AUTO; then
            printf '%s\n' 'ListenAddress 127.0.0.1'
        fi
        if [[ "$proto" == "1" ]]; then
            printf '%s\n' \
                'Protocol 1' \
                'PermitRootLogin yes' \
                'PasswordAuthentication yes' \
                'RSAAuthentication yes' \
                'UsePAM yes' \
                "Cipher ${ssh1cipher}" \
                'HostKey /etc/ssh/ssh_host_key' \
                'LogLevel DEBUG3'
        else
            # AEAD（chacha20-poly1305 / AES-GCM）等不协商传统 MAC，MAC 为空，
            # 此时不写 MACs 指令，避免 "MACs " 空值导致 sshd 拒绝配置。
            printf '%s\n' \
                'Protocol 2' \
                'PermitRootLogin yes' \
                'PasswordAuthentication yes' \
                'PubkeyAuthentication yes' \
                'UsePAM yes' \
                "KexAlgorithms ${kex}" \
                "Ciphers ${cipher}" \
                'LogLevel DEBUG3'
            if [[ -n "$mac" ]]; then
                printf '%s\n' "MACs ${mac}"
            fi
            # HostKeyAlgorithms 指令是 OpenSSH 6.5+ 才引入的。
            # CentOS 6 的 OpenSSH 5.3 不支持该指令，写入会导致
            # sshd -t 校验失败（bad configuration option）。
            # 因此仅当 OpenSSH >= 6.5 时才写入；旧版本通过下方
            # HostKey 指令指定 key 文件来决定 host key 算法。
            if [[ -n "$SSHD_VER_MAJOR" ]] && \
                { (( SSHD_VER_MAJOR > 6 )) || { [[ "$SSHD_VER_MAJOR" == 6 ]] && (( SSHD_VER_MINOR >= 5 )); }; }; then
                printf '%s\n' "HostKeyAlgorithms ${hostkey}"
            fi
            if [[ -n "$compression" ]]; then
                case "$compression" in
                    zlib@openssh.com) printf '%s\n' 'Compression delayed' ;;
                    zlib) printf '%s\n' 'Compression yes' ;;
                    none) printf '%s\n' 'Compression no' ;;
                esac
            fi
            case "$hostkey" in
                ssh-dss) printf '%s\n' 'HostKey /etc/ssh/ssh_host_dsa_key' ;;
                ssh-ed25519) printf '%s\n' 'HostKey /etc/ssh/ssh_host_ed25519_key' ;;
                ssh-ed448) printf '%s\n' 'HostKey /etc/ssh/ssh_host_ed448_key' ;;
                ecdsa-*) printf '%s\n' 'HostKey /etc/ssh/ssh_host_ecdsa_key' ;;
                ssh-sm2|sm2) printf '%s\n' 'HostKey /etc/ssh/ssh_host_sm2_key' ;;
                *) printf '%s\n' 'HostKey /etc/ssh/ssh_host_rsa_key' ;;
            esac
        fi
        printf '%s\n' '# --- END UNIFIED TEST OVERRIDES ---'
    } > "$tmp"

    # 原配置全部保留；仅注释全局范围内与本次测试直接冲突的指令。
    awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; print; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1 }
        {
            if (!in_match && $0 ~ /^[[:space:]]*(Port|ListenAddress|Protocol|KexAlgorithms|Ciphers|Cipher|MACs|HostKeyAlgorithms|HostKey|LogLevel|Compression|Include)[[:space:]]+/) {
                print "# UNIFIED_TEST_COMMENTED: " $0
            } else {
                print
            }
        }
    ' "$BACKUP_FILE" >> "$tmp" || { rm -f "$tmp"; return 1; }

    chmod 600 "$tmp"
    cat "$tmp"
    rm -f "$tmp"
}

detect_match_algorithm_overrides() {
    local found=""
    found="$(awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1; next }
        in_match && $0 ~ /^[[:space:]]*(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|HostKey|Cipher|Protocol)[[:space:]]+/ {
            print NR ":" $0
        }
    ' "$BACKUP_FILE" 2>/dev/null || true)"

    if [[ -n "$found" ]]; then
        env_log "WARNING：原始 sshd_config 的 Match 块包含算法/协议覆盖项；测试覆盖已置于 Match 之前，但以下规则已记录："
        while IFS= read -r line; do
            [[ -n "$line" ]] && env_log "  MATCH_OVERRIDE: $line"
        done <<< "$found"
    else
        env_log "Match 算法覆盖检查：未发现 Match 块中的 Kex/Cipher/MAC/HostKey/Protocol 指令"
    fi
}

make_ssh2_config() {
    local idx="$1" desc="$2" kex="$3" cipher="$4" mac="$5" hostkey="$6" target="$7" compression="${8:-}"
    local cfg_content
    cfg_content="$(make_test_config_from_backup 2 "$idx" "$desc" "$kex" "$cipher" "$mac" "$hostkey" "" "$compression")" || return 1
    printf '%s\n' "$cfg_content" > "$target"
}

make_ssh1_config() {
    local idx="$1" desc="$2" cipher="$3" target="$4"
    local cfg_content
    cfg_content="$(make_test_config_from_backup 1 "$idx" "$desc" "" "" "" "" "$cipher")" || return 1
    printf '%s\n' "$cfg_content" > "$target"
}

detect_match_algorithm_overrides

run_auto_ssh2() {
    local kex="$1" cipher="$2" mac="$3" hostkey="$4" output="$5" compression="${6:-}"

    local comp_opt=""
    local hostkey_opt=""
    local mac_opt=""
    case "$compression" in
        zlib@openssh.com|zlib) comp_opt="-o Compression=yes" ;;
        none) comp_opt="-o Compression=no" ;;
    esac
    # AEAD cipher 不协商传统 MAC，MAC 为空时客户端不传 -o MACs=。
    if [[ -n "$mac" ]]; then
        mac_opt="-o MACs=$mac"
    fi
    # OpenSSH 5.3 客户端不可靠支持 HostKeyAlgorithms；CentOS 6 的服务端
    # 已通过 HostKey 文件选择算法，旧客户端无需再传该现代选项。
    if [[ "$SSH_VER" =~ ^[0-9]+\. ]] && {
        (( ${SSH_VER%%.*} > 6 )) ||
        { [[ "$SSH_VER" =~ ^6\. ]] && (( ${SSH_VER#6.} >= 5 )); };
    }; then
        hostkey_opt="-o HostKeyAlgorithms=$hostkey"
    fi

    # KexAlgorithms 作为 ssh 客户端选项在 OpenSSH 5.4 才引入；
    # CentOS 6 的 OpenSSH 5.3 客户端不支持，传了会报 Bad configuration option。
    # 旧版本客户端不限制 KEX，服务端配置已经固定了 KEX，客户端会自动从
    # 服务端提议中接受；因此 5.3 客户端不传该选项即可。
    local kex_opt=""
    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR >= 6 )); then
        kex_opt="-o KexAlgorithms=$kex"
    fi

    local identity_opt=""
    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR >= 6 )); then
        identity_opt="-o IdentitiesOnly=yes"
    fi

    ssh -vvv \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=1 \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        $identity_opt \
        -i "$AUTO_KEY" \
        $kex_opt \
        -o Ciphers="$cipher" \
        $mac_opt \
        $hostkey_opt \
        $comp_opt \
        -p "$PORT" "$LOOPBACK_TARGET" true \
        >"$output" 2>&1
}

run_auto_ssh1() {
    local cipher="$1" output="$2"

    # SSH-1 自动模式也用临时公钥做 RSA 认证（与 SSH-2 一致），
    # 避免 BatchMode=yes + 无密码导致认证必失败。
    local identity_opt=""
    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR >= 6 )); then
        identity_opt="-o IdentitiesOnly=yes"
    fi

    ssh -vvv -1 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=1 \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        $identity_opt \
        -i "$AUTO_SSH1_KEY" \
        -p "$PORT" \
        -c "$cipher" \
        "$LOOPBACK_TARGET" true \
        >"$output" 2>&1
}

# sshd -Q 仅作为诊断信息；跨版本过滤不依赖它。
load_supported_algorithms
{
    echo "----- Environment Algorithm Prediction -----"
    echo "[KEX]"; printf '%s\n' "$SUPPORTED_KEX"
    echo "[CIPHER]"; printf '%s\n' "$SUPPORTED_CIPHER"
    echo "[MAC]"; printf '%s\n' "$SUPPORTED_MAC"
    echo "[HOSTKEY]"; printf '%s\n' "$SUPPORTED_HOSTKEY"
    echo "---------------------------------------------"
} >> "$ENV_FILE"

restore_after_test() {
    local reason="${1:-测试项结束恢复}"
    local skip_restart="${2:-false}"
    local restore_tmp=""

    if [[ -f "$BACKUP_FILE" ]] && grep -qF 'ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT' "$SSHD_CONFIG" 2>/dev/null; then
        restore_tmp="$(mktemp "${SSHD_CONFIG}.restore.XXXXXX" 2>/dev/null || true)"
        if [[ -n "$restore_tmp" ]] && cp -a "$BACKUP_FILE" "$restore_tmp" && mv -f "$restore_tmp" "$SSHD_CONFIG"; then
            log "[恢复] $reason：sshd_config 已恢复"
        else
            log "[恢复] ERROR：$reason：sshd_config 恢复失败"
            RESTORE_FAILED=true
            [[ -n "$restore_tmp" ]] && rm -f "$restore_tmp"
        fi
    elif [[ -f "$BACKUP_FILE" ]]; then
        log "[恢复] WARNING：$reason：sshd_config 已被外部修改（不含测试 marker），跳过恢复以避免覆盖外部修改"
    fi

    # 仅在配置确实被 mv 替换后才需要重启服务恢复；
    # sshd -t/-T 失败路径（配置未替换）传 skip_restart=true 避免不必要的服务中断。
    if ! $skip_restart && $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            service_restart >/dev/null 2>&1 || log "[恢复] WARNING：$reason：sshd 无法恢复为运行状态"
        else
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || true
            fi
        fi
    fi

    rm -f /tmp/algo_client.$$.* /tmp/algo_sshd_t.$$.*
}

record_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" reason="${16}"
    # 类型B（默认配置）标记：从 DEFAULT_FLAGS 按编号取，调用点无需改动。
    local default_supported="${DEFAULT_FLAGS[$((idx - 1))]:-n/a}"

    # 统计口径与 write_result 的合并结果一致：
    #   nr=PASS 且 ar=PASS → PASS；nr=PASS 且 ar=FAIL → AUTH_FAIL(计入 FAIL)
    #   nr 非 PASS → 按其状态归类（FAIL/UNKNOWN/SKIP）
    local overall="$nr"
    case "$nr" in
        PASS) case "$ar" in PASS) overall=PASS ;; FAIL) overall=AUTH_FAIL ;; *) overall=PASS ;; esac ;;
    esac

    case "$overall" in
        PASS) PASS=$((PASS + 1)) ;;
        AUTH_FAIL|FAIL) FAIL=$((FAIL + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
        *) UNKNOWN=$((UNKNOWN + 1)) ;;
    esac

    write_result "$idx" "$desc" "$group" "$proto" \
        "$fk" "$fc" "$fm" "$fh" "$nk" "$nc" "$nm" "$nh" \
        "$nr" "$ar" "$cr" "$default_supported" "$reason"
}

test_one() {
    local idx="$1"
    local p=$((idx - 1))

    local desc="${DESCS[$p]}"
    local kex="${KEXES[$p]}"
    local cipher="${CIPHERS[$p]}"
    local mac="${MACS[$p]}"
    local hostkey="${HOSTKEYS[$p]}"
    local group="${TEST_GROUPS[$p]}"
    local proto="${PROTOCOLS[$p]}"
    local compression="${COMPRESSIONS[$p]}"

    should_run "$idx" "$desc" || return 0

    RUN_INDEX=$((RUN_INDEX + 1))

    local tmp=""
    local client_out=""
    local server_log=""
    local log_before=0
    local server_delta=""
    local reason=""
    local rc=0
    local TEST_START_TIME=""

    local NK=""
    local NC=""
    local NM=""
    local NH=""

    local NR="UNKNOWN"
    local AR="UNKNOWN"
    local CR="UNKNOWN"

    log ""
    log "============================================================"
    log "[协商测试] #${idx} ${desc}"
    if [[ "$proto" == "1" ]]; then
        log "固定：SSH-1 CIPHER：${cipher} SERVER_KEY：${hostkey}"
    else
        log "固定：CIPHER：${cipher}"
        log "测试：KEX：${kex} HOST_KEY：${hostkey} MAC：${mac}"
    fi

    # 客户端完全不支持 SSH-1 时，不进入 SSH-1 协商测试；这属于客户端能力限制，不能判为服务端算法 FAIL。
    # 仅自动模式做此判断：自动模式由本机 ssh 发起连接，其版本决定能否协商 SSH-1。
    # 手动模式由外部客户端（如 CF Worker）连接，客户端能力未知，不做预判，交真实协商判断。
    if $AUTO && [[ "$proto" == "1" && ! "$SSH_VER" =~ ^5\. ]]; then
        NR="SKIP"
        AR="NOT_TESTED"
        CR="CLIENT_REJECTED"
        reason="本机 ssh 客户端版本(${SSH_VER:-unknown})不支持 SSH-1；仅自动模式适用此判断（手动模式由外部客户端连接，不做预判）"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        log "SKIP [#$idx] $desc — $reason"
        return 0
    fi

    # 不在这里使用 sshd -Q 判定服务端能力。CentOS 6/OpenSSH 5.3 的 -Q
    # 不提供现代版本的算法查询；最终能力以本次测试配置的 sshd -t + sshd -T
    # 和真实 SSH 协商为准。

    # CentOS 6 的 DSA 测试只有真正存在 DSA host key 时才执行。
    if [[ "$hostkey" == "ssh-dss" && ! -f /etc/ssh/ssh_host_dsa_key ]]; then
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "SKIP" "NOT_TESTED" "NOT_APPLICABLE" "缺少 /etc/ssh/ssh_host_dsa_key"
        log "SKIP [#$idx] $desc — 缺少 DSA host key"
        return 0
    fi

    # CentOS 6 SSH-1 使用原脚本的 Protocol 1 配置；SSH-2 使用统一配置。
    if [[ "$proto" == "1" ]]; then
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        if ! make_ssh1_config "$idx" "$desc" "$cipher" "$tmp"; then
            rm -f "$tmp"
            NR="SKIP"; AR="NOT_TESTED"; CR="SERVER_CONFIG_GENERATION_FAILED"
            reason="生成 SSH-1 测试配置失败"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "" "" "" "" "$NR" "$AR" "$CR" "$reason"
            log "SKIP [#$idx] $desc — $reason"
            return 0
        fi
    else
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        if ! make_ssh2_config "$idx" "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$tmp" "$compression"; then
            rm -f "$tmp"
            NR="SKIP"; AR="NOT_TESTED"; CR="SERVER_CONFIG_GENERATION_FAILED"
            reason="生成 SSH-2 测试配置失败"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "" "" "" "" "$NR" "$AR" "$CR" "$reason"
            log "SKIP [#$idx] $desc — $reason"
            return 0
        fi
    fi
    chmod 600 "$tmp"

    local syntax_err
    syntax_err="$(mktemp "/tmp/algo_sshd_t.$$.XXXXXX")"

    if ! "$SSHD_BIN" -t -f "$tmp" >"$syntax_err" 2>&1; then
        reason="$(head -3 "$syntax_err" | tr '\n' ' ')"
        rm -f "$syntax_err" "$tmp"

        NR="SKIP"
        AR="NOT_TESTED"
        CR="SERVER_CONFIG_REJECTED"

        log "实际协商：UNKNOWN"
        log "总体结果：SKIP"
        log "原因：sshd -t 配置校验失败：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        return 0
    fi
    rm -f "$syntax_err"

    # -T 读取的是该测试配置最终生效的值。它比全局 -Q 更接近实际
    # 协商，尤其适用于 OpenSSH 5.3/CentOS 6；解析失败时不冒险重启服务。
    local effective_rc=0 effective_unsupported=""
    load_effective_algorithms "$tmp" || effective_rc=$?
    if (( effective_rc != 0 )); then
        NR="SKIP"
        AR="NOT_TESTED"
        CR="SERVER_CONFIG_REJECTED"
        reason="sshd -T -f 临时配置失败"
        log "实际协商：UNKNOWN"
        log "总体结果：SKIP"
        log "原因：$reason"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        rm -f "$tmp"
        restore_after_test "临时配置 -T 校验失败" true
        return 0
    fi

    if [[ "$proto" == "2" ]]; then
        algo_effective_supported kex "$kex" || effective_unsupported+=" KEX[$kex]"
        algo_effective_supported cipher "$cipher" || effective_unsupported+=" CIPHER[$cipher]"
        # AEAD cipher 不协商传统 MAC，其测试组合 MAC 为空，跳过 MAC 校验。
        case "$cipher" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) algo_effective_supported mac "$mac" || effective_unsupported+=" MAC[$mac]" ;;
        esac
        algo_effective_supported key "$hostkey" || effective_unsupported+=" HOSTKEY[$hostkey]"
        if [[ -n "$effective_unsupported" ]]; then
            NR="SKIP"
            AR="NOT_TESTED"
            CR="NOT_APPLICABLE"
            reason="sshd -T 最终配置未启用:$effective_unsupported"
            log "实际协商：UNKNOWN"
            log "总体结果：SKIP"
            log "原因：$reason"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
            rm -f "$tmp"
            restore_after_test "算法不在临时配置有效集合" true
            return 0
        fi
    fi

    mv -f "$tmp" "$SSHD_CONFIG"

    if ! service_restart; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="SERVER_RESTART_FAILED"
        reason="sshd 重启失败"

        log "实际协商：UNKNOWN"
        log "总体结果：UNKNOWN"
        log "原因：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        rm -f "$tmp"
        restore_after_test "sshd 重启失败"
        return 0
    fi

    if ! wait_service_ready; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="SERVER_DOWN"
        reason="sshd 重启后 60 秒内未进入运行状态"

        log "实际协商：UNKNOWN"
        log "总体结果：UNKNOWN"
        log "原因：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        rm -f "$client_out" "$tmp"
        restore_after_test "sshd 启动后异常"
        return 0
    fi

    # 重启后的第二次 -T：确认正在运行的 sshd 实际配置仍与测试配置一致。
    # 不能只相信重启前的临时文件，因为服务包装器、Include、crypto policy
    # 或其他外部修改可能导致最终运行配置发生变化。
    local running_effective_rc=0 running_unsupported=""
    load_effective_algorithms "$SSHD_CONFIG" || running_effective_rc=$?
    if (( running_effective_rc != 0 )); then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="SERVER_CONFIG_MISMATCH"
        reason="sshd 重启后无法读取最终生效配置：sshd -T -f $SSHD_CONFIG"
        log "实际协商：UNKNOWN"
        log "总体结果：UNKNOWN"
        log "原因：$reason"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        restore_after_test "重启后 -T 校验失败"
        return 0
    fi
    if [[ "$proto" == "2" ]]; then
        algo_effective_supported kex "$kex" || running_unsupported+=" KEX[$kex]"
        algo_effective_supported cipher "$cipher" || running_unsupported+=" CIPHER[$cipher]"
        # AEAD 不使用传统 MAC；这里不把测试组合中的占位 MAC 当成运行配置要求。
        case "$cipher" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) algo_effective_supported mac "$mac" || running_unsupported+=" MAC[$mac]" ;;
        esac
        algo_effective_supported key "$hostkey" || running_unsupported+=" HOSTKEY[$hostkey]"
        if [[ -n "$running_unsupported" ]]; then
            NR="UNKNOWN"
            AR="NOT_TESTED"
            CR="SERVER_CONFIG_MISMATCH"
            reason="重启后 sshd -T 有效配置与测试项不一致:$running_unsupported"
            log "实际协商：UNKNOWN"
            log "总体结果：UNKNOWN"
            log "原因：$reason"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
            restore_after_test "重启后有效配置不一致"
            return 0
        fi
    fi

    server_log="$(detect_log_file)"
    TEST_START_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
    if [[ -n "$server_log" ]]; then
        log_before="$(file_size "$server_log")"
    fi

    client_out="$(mktemp "/tmp/algo_client.$$.XXXXXX")"

    if $AUTO; then
        env_log "自动认证：root@127.0.0.1，临时公钥 marker=${AUTO_MARKER}"
        if [[ "$proto" == "1" ]]; then
            run_auto_ssh1 "$cipher" "$client_out"
            rc=$?
        else
            run_auto_ssh2 "$kex" "$cipher" "$mac" "$hostkey" "$client_out" "$compression"
            rc=$?
        fi
    else
        log "手动模式：等待外部客户端（如 CF Worker）发起连接本项。"
        server_delta="$(wait_for_manual_client "$server_log" "$log_before")"
        rc=0
    fi

    if [[ -n "$server_log" ]] && $AUTO; then
        server_delta="$(wait_for_server_log "$server_log" "$log_before")"
    fi

    if ! $AUTO && [[ "$proto" == "2" ]]; then
        NK="$(printf '%s\n' "$server_delta" |
            grep -m1 -E 'kex: algorithm: ' |
            sed 's/.*kex: algorithm: //' | tr -d '\r')"
        NH="$(printf '%s\n' "$server_delta" |
            grep -m1 -E 'kex: host key algorithm: ' |
            sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        NC="$(printf '%s\n' "$server_delta" |
            grep -m1 -E 'server->client cipher: ' |
            sed 's/.*server->client cipher: //' | cut -d, -f1 | tr -d '\r')"
        NM="$(printf '%s\n' "$server_delta" |
            grep -m1 -E 'server->client MAC: ' |
            sed 's/.*server->client MAC: //' | cut -d, -f1 | tr -d '\r')"

        if [[ -z "$NK" ]]; then
            NK="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: (diffie-|ecdh-|curve|gss-).*' |
                sed -E 's/.*kex: (.*)/\1/' | awk '{print $1}' | tr -d '\r')"
        fi
        if [[ -z "$NC" ]]; then
            NC="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: server->client ' |
                awk '{print $4}' | tr -d '\r')"
        fi
        if [[ -z "$NM" ]]; then
            NM="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: server->client ' |
                awk '{print $5}' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'host key algorithm|server host key' |
                sed -E 's/.*(ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+|rsa-sha2-[0-9]+).*/\1/' | tr -d '\r')"
        fi
    fi

    # --------------------------------------------------------
    # 自动模式：优先从 ssh -vvv 得到实际协商参数。
    # 这比用 ssh 退出码判断算法结果准确。
    # --------------------------------------------------------
    if [[ "$proto" == "2" && -s "$client_out" ]]; then
        NK="$(grep -m1 -E 'kex: algorithm: ' "$client_out" |
            sed 's/.*kex: algorithm: //' | tr -d '\r')"
        NH="$(grep -m1 -E 'kex: host key algorithm: ' "$client_out" |
            sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        NC="$(grep -m1 -E 'server->client cipher: ' "$client_out" |
            sed -n 's/.*server->client cipher: \([^ ]*\).*/\1/p' | tr -d '\r')"
        NM="$(grep -m1 -E 'server->client MAC: ' "$client_out" |
            sed -n 's/.*server->client .* MAC: \([^ ]*\).*/\1/p' | tr -d '\r')"

        # OpenSSH 5.x 使用旧式日志格式，例如：
        #   kex: server->client aes256-ctr hmac-sha1 none
        #   kex: client->server aes256-ctr hmac-sha1 none
        # 旧版本没有现代的“algorithm:”字段。
        if [[ -z "$NK" ]]; then
            NK="$(grep -m1 -E 'kex: (diffie-|ecdh-|curve|gss-).*' "$client_out" |
                sed -E 's/.*kex: (.*)/\1/' | awk '{print $1}' | tr -d '\r')"
        fi
        if [[ -z "$NC" ]]; then
            NC="$(grep -m1 -E 'kex: server->client ' "$client_out" |
                sed -n 's/.*server->client \([^ ]*\) .*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NM" ]]; then
            NM="$(grep -m1 -E 'kex: server->client ' "$client_out" |
                sed -n 's/.*server->client [^ ]* \([^ ]*\) .*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(grep -m1 -E 'host key algorithm|server host key' "$client_out" |
                sed -E 's/.*(ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+|rsa-sha2-[0-9]+).*/\1/' | tr -d '\r')"
        fi
    fi

    # 压缩协商结果（仅压缩测试项需要）
    local NCOMP=""
    if [[ -n "$compression" && -s "$client_out" ]]; then
        NCOMP="$(grep -m1 -E 'compression: server->client' "$client_out" |
            sed 's/.*server->client //' | awk '{print $1}' | tr -d '\r')"
    fi

    # --------------------------------------------------------
    # 客户端明确拒绝算法：不把客户端不支持误判成服务端 FAIL。
    # --------------------------------------------------------
    if grep -qiE \
        'unknown cipher|Bad SSH2 cipher|Bad SSH2 KEX|Bad SSH2 MAC|unknown option|Unsupported option' \
        "$client_out" 2>/dev/null; then

        if [[ -z "$NK$NC$NM$NH" ]]; then
            NR="UNKNOWN"
            AR="NOT_TESTED"
            CR="CLIENT_REJECTED"
            reason="$(grep -iE \
                'unknown cipher|Bad SSH2 cipher|Bad SSH2 KEX|Bad SSH2 MAC|unknown option|Unsupported option' \
                "$client_out" | tail -1)"
        fi
    fi

    # --------------------------------------------------------
    # 协商判断
    # --------------------------------------------------------
    if [[ "$NR" == "UNKNOWN" && "$CR" != "CLIENT_REJECTED" ]]; then
        local negotiation_pattern='Unable to negotiate|no matching .*found|no matching .*method|kex_exchange_identification'
        if text_matches "$negotiation_pattern" "$server_delta" || \
           grep -qiE "$negotiation_pattern" "$client_out" 2>/dev/null; then

            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="$(last_matching_text "$negotiation_pattern" "$server_delta")"
            [[ -n "$reason" ]] || reason="$(grep -hiE "$negotiation_pattern" "$client_out" 2>/dev/null | tail -1)"

        elif { [[ "$cipher" == chacha20-poly1305@openssh.com || "$cipher" == aes128-gcm@openssh.com || "$cipher" == aes256-gcm@openssh.com ]] && [[ -n "$NK$NC$NH" ]]; } || \
         [[ -n "$NK$NC$NM$NH" ]]; then
            local mac_matches=true
            case "$cipher" in
                chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                    # AEAD 不协商传统 MAC，日志可能不提取到 NM，直接放行 MAC 比较。
                    mac_matches=true
                    ;;
                *)
                    [[ "$NM" == "$mac" ]] || mac_matches=false
                    ;;
            esac
            if [[ "$NK" == "$kex" && "$NC" == "$cipher" && "$mac_matches" == true && "$NH" == "$hostkey" ]]; then
                if [[ -n "$compression" ]]; then
                    if [[ "$NCOMP" == "$compression" ]]; then
                        NR="PASS"
                    else
                        NR="FAIL"
                        AR="NOT_TESTED"
                        CR="NEGOTIATION_MISMATCH"
                        reason="压缩协商不匹配：期望=$compression 实际=${NCOMP:-UNKNOWN}"
                    fi
                else
                    NR="PASS"
                fi
            else
                NR="FAIL"
                AR="NOT_TESTED"
                CR="NEGOTIATION_MISMATCH"
                reason="客户端 DEBUG3 检测到的实际协商算法与本次固定测试组合不一致"
            fi
        fi
    fi

    # --------------------------------------------------------
    # 认证判断
    # 认证结果独立于协商结果。
    # --------------------------------------------------------
    if [[ "$NR" == "PASS" ]]; then
        # 客户端 DEBUG3 明确出现认证成功时优先采用客户端证据。
        if grep -qiE 'Authenticated to .*|Authentication succeeded' "$client_out" 2>/dev/null; then
            AR="PASS"
            CR="PASS"

        elif text_matches 'Accepted password|Accepted publickey|Accepted keyboard-interactive|User .* authenticated|authentication success' "$server_delta" || \
             grep -qiE \
            'Accepted password|Accepted publickey|Accepted keyboard-interactive|User .* authenticated|authentication success' \
            "$client_out" 2>/dev/null; then

            AR="PASS"
            CR="PASS"

        elif text_matches 'No more authentication methods to try|Permission denied|Failed password|Failed publickey|Failed none|authentication failure' "$server_delta" || \
             grep -qiE \
            'No more authentication methods to try|Permission denied|Failed password|Failed publickey|Failed none|authentication failure' \
            "$client_out" 2>/dev/null; then

            AR="FAIL"
            CR="PASS"

        else
            # 协商已经从客户端 DEBUG3 明确得到实际算法，但认证日志没有
            # 足够证据时不能擅自判 PASS/FAIL。
            AR="UNKNOWN"
            CR="NEGOTIATED"
            reason="${reason:-协商已成功，但没有足够日志准确判断认证结果}"
        fi
    fi

    # SSH-1 的服务端日志是主要判断依据；现代 SSH 客户端可能自身已移除 SSH-1。
    if [[ "$proto" == "1" ]]; then
        if text_matches 'Unable to negotiate|no matching|Connection closed|Did not receive identification' "$server_delta" || \
           grep -qiE 'Unable to negotiate|no matching|Connection closed|Did not receive identification' \
            "$client_out" 2>/dev/null; then
            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="$(last_matching_text 'Unable to negotiate|no matching|Connection closed|Did not receive identification' "$server_delta")"
            [[ -n "$reason" ]] || reason="$(grep -hiE 'Unable to negotiate|no matching|Connection closed|Did not receive identification' "$client_out" 2>/dev/null | tail -1)"
        elif text_matches 'Accepted|authentication success|User .* authenticated' "$server_delta" || \
             grep -qiE 'Accepted|authentication success|User .* authenticated' \
            "$client_out" 2>/dev/null; then
            NR="PASS"
            AR="PASS"
            CR="PASS"
        elif text_matches 'Failed password|Failed publickey|Failed none|authentication failure' "$server_delta" || \
             grep -qiE 'Failed password|Failed publickey|Failed none|authentication failure' \
            "$client_out" 2>/dev/null; then
            NR="PASS"
            AR="FAIL"
            CR="PASS"
        elif grep -qiE 'unknown option|Unsupported|Protocol major versions differ|SSH protocol version 1' \
            "$client_out" 2>/dev/null; then
            NR="UNKNOWN"
            AR="NOT_TESTED"
            CR="CLIENT_REJECTED"
            reason="$(grep -iE \
                'unknown option|Unsupported|Protocol major versions differ|SSH protocol version 1' \
                "$client_out" | tail -1)"
        else
            NR="UNKNOWN"
            AR="UNKNOWN"
            CR=$([[ "$rc" -eq 0 ]] && echo "UNKNOWN" || echo "CLIENT_EXIT_${rc}")
            reason="${reason:-SSH-1 未找到足以证明协商/认证结果的日志}"
        fi
    fi

    # --------------------------------------------------------
    # 手动模式实际协商参数
    #
    # 原 4 脚本的手动模式不是由本脚本启动客户端，因此不能伪造
    # “实际协商”字段。若服务端 DEBUG3 日志能明确给出算法则记录，
    # 否则记录 UNKNOWN。
    # --------------------------------------------------------
    if ! $AUTO && [[ "$proto" == "2" ]]; then
        if [[ -z "$NK" ]]; then
            NK="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: algorithm: ' |
                sed 's/.*kex: algorithm: //' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: host key algorithm: ' |
                sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        fi
        if [[ -z "$NC" ]]; then
            NC="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'server->client cipher: ' |
                sed -n 's/.*server->client cipher: \([^ ]*\).*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NM" ]]; then
            NM="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'server->client MAC: ' |
                sed -n 's/.*server->client .* MAC: \([^ ]*\).*/\1/p' | tr -d '\r')"
        fi
    fi

    if [[ "$NR" == "PASS" && "$AR" == "UNKNOWN" && -z "$reason" ]]; then
        reason="协商成功；认证状态无法从当前日志准确确定"
    fi

    if [[ "$proto" == "1" ]]; then
        log "实际协商：SSH-1 CIPHER=${NC:-UNKNOWN} SERVER_KEY=${NH:-ssh-rsa1/UNKNOWN}"
    else
        log "实际协商：KEX=${NK:-UNKNOWN} CIPHER=${NC:-UNKNOWN} MAC=${NM:-UNKNOWN} HOST_KEY=${NH:-UNKNOWN}"
    fi
    # 合并协商结果与认证结果为一行总体结果（与 write_result/record_result 口径一致）：
    #   NR=PASS 且 AR=PASS → PASS；NR=PASS 且 AR=FAIL → AUTH_FAIL；其它取 NR。
    local overall_txt="$NR"
    if [[ "$NR" == "PASS" ]]; then
        case "$AR" in
            PASS) overall_txt="PASS" ;;
            FAIL) overall_txt="AUTH_FAIL" ;;
            *) overall_txt="PASS" ;;
        esac
    fi
    log "总体结果：${overall_txt}"
    log "客户端结果：${CR}"
    [[ -n "$reason" ]] && log "原因：${reason}"

    # 计数只反映最终分类，不与 ssh 命令退出码直接绑定。
    record_result "$idx" "$desc" "$group" "$proto" \
        "$kex" "$cipher" "$mac" "$hostkey" \
        "$NK" "$NC" "$NM" "$NH" \
        "$NR" "$AR" "$CR" "$reason"

    rm -f "$client_out" "$tmp"
    restore_after_test "测试项 #${idx} 完成"
}

log "============================================================"
log "SSH 算法协商统一测试"
log "系统：$OS_PRETTY"
log "OpenSSH：${SSH_VERSION_STR:-unknown}"
log "Profile：$PROFILE"
log "模式：$($AUTO && echo 自动 || echo 手动)"
log "端口：$PORT"
log "测试项：$TEST_INDEX"
log "版本过滤：$FILTERED_TESTS 项"
log "结果格式：$RESULT_FORMAT"
log "============================================================"

env_log "配置备份: $BACKUP_FILE"
env_log "测试项总数: $TEST_INDEX"
env_log "版本过滤项数: $FILTERED_TESTS"
env_log "初始服务状态: $($INITIAL_SERVICE_ACTIVE && echo running || echo stopped/unknown)"
env_log "初始 crypto-policy: ${INITIAL_CRYPTO_POLICY:-未检测到}"

for ((i=1; i<=TEST_INDEX; i++)); do
    # 恢复失败时立即中止，避免 sshd 停留在非预期配置下继续测试（结果全部失真）。
    if $RESTORE_FAILED; then
        log "检测到恢复失败，中止剩余测试（SSH 服务可能仍处于测试配置）。"
        exit 1
    fi
    test_one "$i"
done

if [[ "$RESULT_FORMAT" == "json" ]]; then
    printf '\n]\n' >> "$JSON_FILE"
fi

env_log "结束时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
env_log "PASS: $PASS"
env_log "FAIL: $FAIL"
env_log "UNKNOWN: $UNKNOWN"
env_log "SKIP: $SKIP"
env_log "配置恢复要求: 已注册 EXIT/INT/TERM cleanup"

log ""
log "============================================================"
log "测试完成"
log "PASS: $PASS"
log "FAIL: $FAIL"
log "UNKNOWN: $UNKNOWN"
log "SKIP: $SKIP"
log "总测试项: $TEST_INDEX"

if [[ "$RESULT_FORMAT" == "csv" ]]; then
    log "结果文件：$CSV_FILE"
else
    log "结果文件：$JSON_FILE"
fi

log "详细测试日志：$LOG_FILE"
log "环境/执行信息：$ENV_FILE"
log "============================================================"

exit 0
