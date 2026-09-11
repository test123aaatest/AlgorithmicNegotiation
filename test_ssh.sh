#!/bin/bash
# ============================================================
# 设计约束：
#   - 不新增原 4 脚本之外的实际测试算法
#   - 自动识别发行版/SSH 版本；识别失败不测试，正常退出
#   - 必须 root（--list 除外）
#   - 默认端口 22
#   - 保留手动模式；--auto 使用本地 127.0.0.1
#   - 测试期间默认强制 sshd 只监听 127.0.0.1，防止临时放开的
#     PermitRootLogin/PasswordAuthentication 暴露到外网；
#     跨主机测试需显式 --allow-remote
#   - 每次只修改一个测试配置，测试完成后恢复
#   - 协商结果与认证结果分离
#   - 算法结果不与 SSH 客户端退出码直接绑定
#   - 保留详细测试日志、环境/执行信息、结构化结果；统一写入 TXT
#
# 输出（当前目录）：
#   仅 1 个 TXT；测试过程中实时同时输出到终端
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
#   sudo ./test_ssh.sh                # 手动模式（默认，每项测试需手动触发/确认）
#   sudo ./test_ssh.sh --auto          # 自动模式（本地回环客户端自动触发）
#   sudo ./test_ssh.sh --list          # 只列出当前环境的测试项，不改动系统
#   sudo ./test_ssh.sh --only=3        # 只运行编号为 3 的测试项（可与 --auto 组合）
#   sudo ./test_ssh.sh --only=blowfish # 只运行描述包含 blowfish 的测试项
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
TMP_DIR="$BASE_DIR"

AUTO=false
LIST_ONLY=false
# 默认强制 sshd 只监听回环地址 127.0.0.1，避免测试期间（临时放开
# PermitRootLogin/PasswordAuthentication）把 root 登录暴露到外网。
# 确有跨主机测试需求时才用 --allow-remote 显式放开。
ALLOW_REMOTE=false
CRYPTO_POLICY_TOOL=""
CRYPTO_POLICY_MODE="${CRYPTO_POLICY_MODE:-capability}"

ONLY_FILTER=""

SSHD_CONFIG="/etc/ssh/sshd_config"
STATE_ROOT="/var/lib/ssh-algo-unified"
STATE_DIR="${STATE_ROOT}/${TS}_$$"
LOCK_DIR="/var/run/ssh-algo-unified.lock"
BACKUP_FILE="${STATE_DIR}/sshd_config.backup"
AUTO_KEY="${BASE_DIR}/.algo_test_key.$$"
AUTO_PUB="${AUTO_KEY}.pub"
AUTO_SSH1_KEY="${BASE_DIR}/.algo_test_ssh1_key.$$"
AUTO_SSH1_PUB="${AUTO_SSH1_KEY}.pub"
AUTO_MARKER="algo-test-auto-key"
LOOPBACK_TARGET="root@127.0.0.1"
# 默认端口 22；可用 --port= 覆盖
PORT=22

# 日志先落在当前工作目录；若该目录不可写/已被删除（如 cd 到已删除目录），
# mktemp 会失败，此时回退到 /tmp，仅当两处都失败才退出，避免脚本完全无法运行。
LOG_FILE="$(mktemp "${BASE_DIR}/ssh_algorithm_test_${TS}_XXXXXX.txt" 2>/dev/null)" || \
    LOG_FILE="$(mktemp "/tmp/ssh_algorithm_test_${TS}_XXXXXX.txt" 2>/dev/null)" || {
    echo "错误：无法创建安全日志文件（已尝试 ${BASE_DIR} 与 /tmp）" >&2
    exit 1
}
chmod 600 "$LOG_FILE" || {
    echo "错误：无法设置日志文件权限：$LOG_FILE" >&2
    exit 1
}

RESTORED=false
# 恢复失败标记：任意恢复步骤失败即中止脚本并带非零退出码退出，
# 避免 sshd 以测试配置继续运行导致后续测试全部失真。
RESTORE_FAILED=false
# restore_all 的返回码（0=已完整恢复，1=存在恢复失败项）。由 trap 调用点
# 读取，用于决定最终退出码，避免在 restore_all 内部直接 exit。
RESTORE_EXIT_CODE=0
# 崩溃自愈（systemd drop-in / SysV crontab @reboot）是否不可用。
# 为 true 时表示：环境缺少 crontab、或自愈安装失败，已降级为"无自愈模式"
# 继续测试。这只影响"崩溃/断电后的开机兜底"，不影响本次测试与结束恢复，
# 但会在结束时的汇总中如实提示，避免用户误以为自愈已生效。
RECOVERY_SELFHEAL_UNAVAILABLE=false
# 当前测试项启动的 ssh 客户端后台 PID。测试项正常结束时会自行 wait 回收；
# 若脚本在客户端运行期间被 INT/TERM/EXIT trap 打断，restore_all 会据此处
# 记录的 PID 终止并回收该客户端，避免残留进程继续占用 sshd 连接。
CLIENT_PID=""
TEST_INDEX=0
RUN_INDEX=0
PASS=0
FAIL=0
UNKNOWN=0
SKIP=0
# WARN：协商成功但存在需人工关注的偏差（如 SSH-1 cipher 请求值与服务端
# 实际落地值不一致的"降级"）。单独计数，不计入 FAIL，也不混入 UNKNOWN。
WARN=0
FILTERED_TESTS=0
SERVER_FILTERED_TESTS=0
SERVER_UNSUPPORTED_TESTS=0
SERVER_UNKNOWN_TESTS=0
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
DEFAULT_COMPRESSION=""
DEFAULT_CONFIG_LOADED=false

INITIAL_SERVICE_ACTIVE=false
INITIAL_SERVICE_KNOWN=false
INITIAL_CRYPTO_POLICY=""
CRYPTO_POLICY_CHANGED=false
# 本脚本实际写入的 crypto-policy 值（仅在成功切换时置位）。恢复时用于
# 精确判断当前值是否仍为本脚本所写。
CRYPTO_POLICY_APPLIED=""
GENERATED_HOST_KEYS=()
GENERATED_HOST_KEYS_FILE="${STATE_DIR}/generated_hostkeys.list"
CRYPTO_POLICY_STATE_FILE="${STATE_DIR}/crypto_policy.state"
# 记录本测试覆盖前已存在的原文件备份（RESTORE_HELPER / systemd drop-in 等），
# 恢复时原样还原，避免覆盖/删除管理员已有配置。
PREEXISTING_BACKUPS=()
# 说明：本脚本的测试临时文件（algo_client.* / algo_sshd_t.* / ssh_algo_probe.*
# / ssh_algo_single.* / ssh1probe.*）统一创建于受保护的 $TMP_DIR（=STATE_DIR）
# 内，恢复时按这些受控前缀 glob 清理；/etc/ssh 下的临时文件则按
# ALGO_TEST_ACTIVE_MARKER 内容过滤后再删。因此不再维护逐文件登记清单，
# 避免"设计与实现不一致"。若日后需要更精细的清理，可在此恢复登记数组。
AUTO_AUTH_KEY_ADDED=false
AUTHORIZED_KEYS_FILE="/root/.ssh/authorized_keys"
AUTHORIZED_KEYS_BACKUP=""
AUTHORIZED_KEYS_WAS_ABSENT=false
SSH_DIR_WAS_ABSENT=false
SSH_DIR_MODE_BEFORE=""
SSH_DIR_UID_BEFORE=""
SSH_DIR_GID_BEFORE=""
RESTORE_HELPER="/usr/local/sbin/ssh-algo-unified-restore"
PID_FILE="/var/run/ssh-algo-unified.pid"
SYSTEMD_DROPIN_DIR=""
SYSTEMD_DROPIN_FILE=""
CRON_TAG="# SSH_ALGO_UNIFIED_RECOVERY"
STATE_DIR_CREATED=false
RESTORE_HELPER_PREEXISTING=false
SYSTEMD_DROPIN_PREEXISTING=false
CONFIG_RESTORED_CONFIRMED=false
LOCK_ACQUIRED=false
# 是否已开始改动宿主状态。仅在 backup_config 成功（备份已落盘）后置真。
# EXIT trap 早于 backup_config 触发时（如抢锁失败、sshd_config 缺失导致 die），
# 系统尚未被改动，此时应跳过整套恢复流程，避免把"什么都没做"误报成"恢复失败"。
STATE_MUTATION_STARTED=false

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

# 注意：脚本启用了 set -u。declare -a/-A 只声明、未赋值时，空数组上的
# ${#arr[@]} 会触发 "unbound variable" 直接崩溃（bash 各版本均如此，即使
# 5.x）。因此这里统一用 =() 显式初始化为空数组。
declare -a DESCS=() KEXES=() CIPHERS=() MACS=() HOSTKEYS=() TEST_GROUPS=() PROTOCOLS=() COMPRESSIONS=() DEFAULT_FLAGS=() PRECHECK_STATUS=() PRECHECK_REASON=()
# 跨 loader 共享的去重集合：所有动态生成器共用，避免 openssh8 等多 loader
# 场景下不同生成器产生重复四元组。bash 关联数组，需 bash>=4。
declare -A GLOBAL_SEEN=()
declare -A PLAN_COVERAGE_SEEN=()
declare -A ACTUAL_SSH1_COVERAGE_SEEN=()
declare -A ACTUAL_SSH2_COVERAGE_SEEN=()
declare -A PREEXISTING_PATH_SEEN=()
declare -a NORMAL_CANDIDATE_KEX=() NORMAL_CANDIDATE_CIPHER=() NORMAL_CANDIDATE_MAC=() NORMAL_CANDIDATE_HOSTKEY=() NORMAL_CANDIDATE_COMPRESSION=()
RESULT_COMPRESSION="N/A"
RESULT_COMPRESSION_ACTUAL="UNKNOWN"
RESULT_COMMAND="NOT_RUN"
RESULT_CLIENT_PROCESS="NOT_RUN"
AUTH_ADDED_LINES_FILE=""
fallback_cipher_for_mac=""

hostkey_file_identity() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        ssh-keygen -lf "$file" 2>/dev/null | awk 'NR == 1 {print $2}'
    fi
}

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
    # 仅在原文件不存在时生成；成功后立即登记。生成失败/半成品全部清理。
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
            if [[ -n "${STATE_DIR_CREATED:-}" && "$STATE_DIR_CREATED" == true ]]; then
                local private_id public_id
                private_id="$(hostkey_file_identity "$path" 2>/dev/null || true)"
                public_id="$(hostkey_file_identity "${path}.pub" 2>/dev/null || true)"
                printf '%s\t%s\t%s\n' "$path" "$private_id" "$public_id" >> "$GENERATED_HOST_KEYS_FILE" || true
                chmod 600 "$GENERATED_HOST_KEYS_FILE" 2>/dev/null || true
                if [[ -z "$private_id" || -z "$public_id" ]]; then
                    env_log "WARNING：无法保存 HostKey 身份，恢复时将拒绝删除该文件：$path"
                fi
            fi
            env_log "本次测试新生成 HostKey: $path"
        else
            rm -f "$path" "${path}.pub"
            env_log "WARNING：HostKey 生成失败，已清理半成品：$path"
        fi
    done
}

prepare_auto_key() {
    # /root/.ssh 本身也可能原来不存在或拥有非 0700 权限；测试不能把这些状态遗失。
    if [[ -d /root/.ssh ]]; then
        SSH_DIR_WAS_ABSENT=false
        SSH_DIR_MODE_BEFORE="$(stat -c %a /root/.ssh 2>/dev/null || stat -f %Lp /root/.ssh 2>/dev/null || true)"
        SSH_DIR_UID_BEFORE="$(stat -c %u /root/.ssh 2>/dev/null || true)"
        SSH_DIR_GID_BEFORE="$(stat -c %g /root/.ssh 2>/dev/null || true)"
    else
        SSH_DIR_WAS_ABSENT=true
        SSH_DIR_MODE_BEFORE=""
        SSH_DIR_UID_BEFORE=""
        SSH_DIR_GID_BEFORE=""
        mkdir -p /root/.ssh || return 1
    fi
    chmod 700 /root/.ssh || return 1

    if [[ "$SSH_DIR_WAS_ABSENT" == true ]]; then
        : > "${BACKUP_FILE}.sshdir.absent"
    else
        rm -f "${BACKUP_FILE}.sshdir.absent"
    fi
    {
        printf '%s\n' "$SSH_DIR_MODE_BEFORE"
        printf '%s\n' "$SSH_DIR_UID_BEFORE"
        printf '%s\n' "$SSH_DIR_GID_BEFORE"
    } > "${BACKUP_FILE}.sshdir.state"
    chmod 600 "${BACKUP_FILE}.sshdir.state" 2>/dev/null || true

    rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"

    # 在修改 authorized_keys 前保存精确快照，支持正常退出与 crash/reboot recovery。
    AUTHORIZED_KEYS_BACKUP="${BACKUP_FILE}.authkeys"
    AUTH_ADDED_LINES_FILE="${BACKUP_FILE}.authkeys.added"
    if [[ -e "$AUTHORIZED_KEYS_FILE" ]]; then
        cp -a "$AUTHORIZED_KEYS_FILE" "$AUTHORIZED_KEYS_BACKUP" || return 1
        AUTHORIZED_KEYS_WAS_ABSENT=false
        rm -f "${BACKUP_FILE}.authkeys.absent"
    else
        : > "${BACKUP_FILE}.authkeys.absent"
        AUTHORIZED_KEYS_WAS_ABSENT=true
        rm -f "$AUTHORIZED_KEYS_BACKUP"
    fi
    : > "${BACKUP_FILE}.authkeys.active"

    # CentOS 6 OpenSSH 5.3 不支持 ed25519，失败则回退 RSA。
    if ! ssh-keygen -t ed25519 -f "$AUTO_KEY" -N "" -q 2>/dev/null; then
        ssh-keygen -t rsa -b 2048 -f "$AUTO_KEY" -N "" -q || return 1
    fi

    touch "$AUTHORIZED_KEYS_FILE"
    local auth_tmp
    auth_tmp="$(mktemp /root/.ssh/authorized_keys.prepare.XXXXXX)" || return 1
    cat "$AUTHORIZED_KEYS_FILE" > "$auth_tmp" 2>/dev/null || true
    : > "$AUTH_ADDED_LINES_FILE"
    printf '%s %s\n' "$(cat "$AUTO_PUB")" "$AUTO_MARKER" | tee -a "$auth_tmp" "$AUTH_ADDED_LINES_FILE" >/dev/null

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
        printf '%s %s\n' "$(cat "$AUTO_SSH1_PUB")" "$AUTO_MARKER" | tee -a "$auth_tmp" "$AUTH_ADDED_LINES_FILE" >/dev/null
    fi
    chmod 600 "$auth_tmp"
    chmod 600 "$AUTH_ADDED_LINES_FILE"
    if ! mv -f "$auth_tmp" "$AUTHORIZED_KEYS_FILE"; then
        rm -f "$auth_tmp"
        return 1
    fi
    AUTO_AUTH_KEY_ADDED=true
}

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
        # 记录本脚本实际写入的值。恢复时必须精确比对"当前值 == 我写入的值"，
        # 而不是"当前值 == LEGACY 这个常量"，否则别的进程/管理员在测试期间
        # 恰好也把策略改成 LEGACY 时，会被误判为"是我改的"而被覆盖。
        CRYPTO_POLICY_APPLIED="LEGACY"
        if [[ -n "${STATE_DIR_CREATED:-}" && "$STATE_DIR_CREATED" == true && -n "$INITIAL_CRYPTO_POLICY" ]]; then
            # 状态文件写两行：第 1 行=本脚本写入的值（恢复时的比对基准），
            # 第 2 行=测试前的原值（恢复目标）。崩溃自愈 helper 读同一文件，
            # 因此与 restore_all 使用完全一致的"精确比对"语义，不会把他人
            # 恰好在测试期间设成的 LEGACY 误判为本脚本所为而覆盖。
            {
                printf '%s\n' "$CRYPTO_POLICY_APPLIED"
                printf '%s\n' "$INITIAL_CRYPTO_POLICY"
            } > "$CRYPTO_POLICY_STATE_FILE" || true
            chmod 600 "$CRYPTO_POLICY_STATE_FILE" 2>/dev/null || true
        fi
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
        --port=*)
            PORT="${arg#--port=}"
            if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
                echo "错误：--port 必须是 1-65535 的纯数字（收到: '$PORT'）" >&2
                exit 1
            fi
            ;;
        -h|--help)
            # 取脚本自身的名字，避免重命名后帮助文案与实际不符。
            # $0 可能带路径（./x.sh、/a/b/x.sh）或被人为 fork 调用，
            # 故取 basename；取不到时回退到通用名。
            SELF_NAME="$(basename -- "${0:-test_ssh.sh}" 2>/dev/null)"
            [[ -n "$SELF_NAME" ]] || SELF_NAME="test_ssh.sh"
            cat <<EOF
用法: sudo ./${SELF_NAME} [选项]

选项:
  (无参数)           手动模式（默认，每项测试需手动触发/确认）
  --auto             自动模式（本地回环客户端自动触发）
  --list             只列出当前环境的测试项，不改动系统
  --only=N           只运行编号为 N 的测试项（可与 --auto 组合）
  --only=keyword     只运行描述包含 keyword 的测试项
  --port=N           指定测试端口（默认 22）
  --allow-remote     允许 sshd 测试期间监听非回环地址（默认仅 127.0.0.1）
                     注意：测试会临时开启 PermitRootLogin/PasswordAuthentication，
                     放开监听范围意味着这些弱配置对外网可见，仅在隔离网络中使用。
  -h, --help         显示此帮助信息
EOF
            exit 0
            ;;
        --allow-remote)
            ALLOW_REMOTE=true
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

initialize_log_file() {
    # 把日志从当前目录（可能是普通用户可读写的 /tmp 等）迁到受保护的
    # 状态目录下（0700 目录 + 0600 文件）。STATE_DIR 形如
    # /var/lib/ssh-algo-unified/<TS>_<PID>，取其父目录 STATE_ROOT。
    local log_dir="${STATE_DIR%/*}"
    local prev_log="$LOG_FILE"

    # 注意 SC2174：mkdir -p 的 -m 只作用于最深层目录，父目录（如
    # /var/lib/ssh-algo-unified 乃至 /var/lib）不受其约束。这里分层创建
    # 并对每一层显式 chmod，避免中间目录以默认 umask 权限裸露。
    local p _created=""
    local IFS='/'
    local acc=""
    for p in $log_dir; do
        [[ -n "$p" ]] || continue
        acc="${acc:+$acc/}$p"
        [[ -e "$acc" ]] && continue
        mkdir "$acc" 2>/dev/null || break
        _created="$acc"
    done
    [[ -n "$_created" ]] && chmod 700 "$_created" 2>/dev/null || true

    if [[ -d "$log_dir" && -w "$log_dir" ]]; then
        if LOG_FILE="$(mktemp "${log_dir}/ssh_algorithm_test_${TS}_XXXXXX.txt" 2>/dev/null)"; then
            if chmod 600 "$LOG_FILE" 2>/dev/null; then
                [[ -n "$prev_log" && -f "$prev_log" ]] && rm -f "$prev_log" 2>/dev/null || true
                return 0
            fi
        fi
    fi

    # 无法落盘到受保护目录时回退到原先的 BASE_DIR 日志，而不是直接退出，
    # 避免只读运行目录导致脚本完全无法运行。
    LOG_FILE="$prev_log"
    if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
        printf '%s\n' "[警告] 无法在受保护目录 $log_dir 创建日志，继续使用当前目录日志：$LOG_FILE"
        return 0
    fi
    echo "错误：无法创建安全日志文件" >&2
    exit 1
}

env_log() {
    # 环境/执行信息与测试结果统一进入同一个 TXT，并实时显示到终端。
    log "[环境] $*"
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

    # sshd -V 在 OpenSSH < 7.2 上不可用于版本解析（如 CentOS 6/OpenSSH 5.3）。
    # 必须先探测 INIT，再在典型 SysV 场景下用同机 ssh 客户端版本做保守回退。
    if [[ -z "$SSHD_VER_MAJOR" ]] && [[ -n "$SSH_VER_MAJOR" ]] && [[ "$INIT" == "sysv/service" ]]; then
        SSHD_VER_MAJOR="$SSH_VER_MAJOR"
        SSHD_VER_MINOR="${SSH_VER_MINOR:-0}"
        SSHD_VER="$SSH_VERSION_STR"
        env_log "sshd -V 不可用（OpenSSH < 7.2），在 SysV 环境回退到客户端版本: ${SSH_VER}"
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
    # 只认 /etc/os-release 的 ID 字段（已解析为 OS_ID），不再对整份文件做
    # 子串匹配——后者会把 PRETTY_NAME/注释里偶然出现的 "openeuler" 也当成
    # openEuler。注意 openEuler 官方 os-release 里 ID="openEuler"（大写 E），
    # 故比较必须大小写不敏感，否则本应识别的 openEuler 机器会全部落到版本
    # 分支、丢失国密/SM 测试与 sm2 主机密钥准备。
    # 同时要求 sshd 与配置文件可用，与其它画像保持一致：否则后续
    # server_filter_status 会因 SSHD_BIN 为空全部返回 PRECHECK_ERROR，
    # 生成大量 UNKNOWN 项却不具备真实测试条件。
    local os_id_lc="${OS_ID,,}"
    if [[ "$os_id_lc" == "openeuler" ]] && [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]]; then
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
    [[ -n "$WORKER_CIPHERS" ]] && return 0
    # 这是 Worker 已实现的完整算法基线
    WORKER_SSH1_CIPHERS=$'3des\nblowfish\nidea\narcfour\ndes'
    WORKER_CIPHERS=$'chacha20-poly1305@openssh.com\naes256-gcm@openssh.com\naes128-gcm@openssh.com\naes256-ctr\naes192-ctr\nsm4-ctr\naes128-ctr\naes256-cbc\naes192-cbc\naes128-cbc\nrijndael-cbc@lysator.liu.se\ntwofish256-cbc\ntwofish128-cbc\n3des-ctr\n3des-cbc\ncast128-cbc\nblowfish-cbc\narcfour256\narcfour128\narcfour\ndes-cbc'
    WORKER_KEX=$'mlkem768x25519-sha256\nsntrup761x25519-sha512@openssh.com\nsntrup761x25519-sha512\ncurve25519-sha256\ncurve25519-sha256@libssh.org\ncurve448-sha512\necdh-sha2-nistp521\necdh-sha2-nistp384\necdh-sha2-nistp256\nsm2-sm3\nsm2_sm3\nsm2kex\ndiffie-hellman-group18-sha512\ndiffie-hellman-group17-sha512\ndiffie-hellman-group16-sha512\ndiffie-hellman-group15-sha512\ndiffie-hellman-group-exchange-sha512\ndiffie-hellman-group14-sha256\ndiffie-hellman-group-exchange-sha256\ndiffie-hellman-group14-sha1\ndiffie-hellman-group-exchange-sha1\ndiffie-hellman-group5-sha1\ndiffie-hellman-group2-sha1\ndiffie-hellman-group1-sha1\necdh-sha2-nistb409\necdh-sha2-nistb233\necdh-sha2-nistk163'
    WORKER_HOSTKEYS=$'ssh-ed25519-cert-v01@openssh.com\nssh-ed448\nssh-ed25519\nssh-sm2\nsm2\necdsa-sha2-nistp521-cert-v01@openssh.com\necdsa-sha2-nistp384-cert-v01@openssh.com\necdsa-sha2-nistp256-cert-v01@openssh.com\necdsa-sha2-nistp521\necdsa-sha2-nistp384\necdsa-sha2-nistp256\nrsa-sha2-512-cert-v01@openssh.com\nrsa-sha2-256-cert-v01@openssh.com\nrsa-sha2-512\nrsa-sha2-256\nssh-rsa-cert-v01@openssh.com\nssh-rsa\nssh-dss-cert-v01@openssh.com\nssh-dss'
    WORKER_MACS=$'hmac-sha2-512-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\nhmac-sm3-etm@openssh.com\numac-128-etm@openssh.com\numac-64-etm@openssh.com\nhmac-sha2-512\nhmac-sha2-256\nhmac-sm3\numac-128@openssh.com\numac-64@openssh.com\nhmac-ripemd160-etm@openssh.com\nhmac-ripemd160@openssh.com\nhmac-sha1-etm@openssh.com\nhmac-sha1\nhmac-sha1-96-etm@openssh.com\nhmac-sha1-96\nhmac-md5-etm@openssh.com\nhmac-md5\nhmac-md5-96-etm@openssh.com\nhmac-md5-96'
    readonly WORKER_SSH1_CIPHERS WORKER_CIPHERS WORKER_KEX WORKER_HOSTKEYS WORKER_MACS
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
    DEFAULT_COMPRESSION="$(printf '%s\n' "$output" | awk '$1 == "compression" { print $2 }')"
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
        compression)
            # 注意：sshd -T 的 compression 只输出 no/yes；"Compression delayed"
            # 也被归一化为 yes，无法据此区分 zlib 与 zlib@openssh.com。因此
            # 当 -T 显示 yes 时，两种压缩算法都视为默认可用（否则会把默认启用
            # 的 zlib@openssh.com 恒判为 default=no）。
            case "$algo" in
                none) [[ "$DEFAULT_COMPRESSION" == "no" ]] ;;
                zlib|zlib@openssh.com) [[ "$DEFAULT_COMPRESSION" == "yes" ]] ;;
                *) return 1 ;;
            esac
            return
            ;;
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
                # ecdsa-* 需按曲线精确匹配：单个 ssh_host_ecdsa_key 只承载
                # nistp256/384/521 中的一条曲线。注意不能仅凭
                # DEFAULT_HOSTKEY_ALGORITHMS（hostkeyalgorithms 是"允许清单"，
                # 即使无匹配密钥也会列出算法名）判定，必须核对默认 HostKey 文件
                # 中是否存在该曲线，否则会把 nistp384/nistp521 误判为默认支持。
                ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|\
                ecdsa-sha2-nistp256-cert-v01@openssh.com|ecdsa-sha2-nistp384-cert-v01@openssh.com|ecdsa-sha2-nistp521-cert-v01@openssh.com)
                    printf '%s\n' "$DEFAULT_HOSTKEY" | grep -Eq '(^|/)ssh_host_ecdsa_key$' || return 1
                    [[ -n "$(hostkey_private_file "$algo" 2>/dev/null || true)" ]] && return 0
                    return 1 ;;
                ecdsa-*)
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

hostkey_certificate_required() {
    local key_file
    [[ "$1" == *-cert-v01@openssh.com ]] || return 1
    key_file="$(hostkey_private_file "$1" 2>/dev/null || true)"
    [[ -n "$key_file" ]] || return 1
    printf '%s-cert.pub\n' "$key_file"
}

ecdsa_key_curve_bits() {
    # 返回 ECDSA 私钥的实际曲线位长（256/384/521）；无法判定时输出空。
    # ssh-keygen -l -f <key> 首列即为曲线位长，是判断 nistp256/384/521 的
    # 可靠依据——同一个 ssh_host_ecdsa_key 文件只承载一条曲线。
    local key_file="$1" bits
    [[ -f "$key_file" ]] || return 1
    command -v ssh-keygen >/dev/null 2>&1 || return 1
    bits="$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk 'NR==1{print $1}')"
    [[ "$bits" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$bits"
}

hostkey_private_file() {
    local algo="$1" base="" want_bits="" keyfile=""
    case "$algo" in
        ssh-rsa|ssh-rsa-cert-v01@openssh.com|rsa-sha2-256|rsa-sha2-256-cert-v01@openssh.com|rsa-sha2-512|rsa-sha2-512-cert-v01@openssh.com)
            printf '%s\n' /etc/ssh/ssh_host_rsa_key ;;
        ssh-dss|ssh-dss-cert-v01@openssh.com)
            printf '%s\n' /etc/ssh/ssh_host_dsa_key ;;
        ssh-ed25519|ssh-ed25519-cert-v01@openssh.com)
            printf '%s\n' /etc/ssh/ssh_host_ed25519_key ;;
        ssh-ed448|ssh-ed448-cert-v01@openssh.com)
            printf '%s\n' /etc/ssh/ssh_host_ed448_key ;;
        ecdsa-sha2-nistp256|ecdsa-sha2-nistp256-cert-v01@openssh.com)
            base=ecdsa-sha2-nistp256; want_bits=256 ;;
        ecdsa-sha2-nistp384|ecdsa-sha2-nistp384-cert-v01@openssh.com)
            base=ecdsa-sha2-nistp384; want_bits=384 ;;
        ecdsa-sha2-nistp521|ecdsa-sha2-nistp521-cert-v01@openssh.com)
            base=ecdsa-sha2-nistp521; want_bits=521 ;;
        ssh-sm2|sm2|sm2-cert-v01@openssh.com)
            printf '%s\n' /etc/ssh/ssh_host_sm2_key ;;
        *)
            return 1 ;;
    esac
    [[ -n "$base" ]] || return 0

    keyfile="/etc/ssh/ssh_host_ecdsa_key"
    [[ -f "$keyfile" ]] || return 1
    # 关键校验：单个 ssh_host_ecdsa_key 只对应一条 ECDSA 曲线。原先 `ecdsa-sha2-*`
    # 通配一律返回该文件，会把 nistp384/nistp521 误判为"支持"，进而在能力预检
    # （HostKeyAlgorithms 只是允许清单，sshd -t/-T 不校验是否真有匹配曲线密钥）
    # 中假阳性通过，生成一个服务端根本无法提供的 NORMAL 协商项，实测必然
    # "no matching host key type found"。这里按实际曲线位长精确匹配。
    local actual_bits
    actual_bits="$(ecdsa_key_curve_bits "$keyfile" 2>/dev/null || true)"
    if [[ -n "$actual_bits" && "$actual_bits" != "$want_bits" ]]; then
        return 1
    fi
    printf '%s\n' "$keyfile"
}

server_hostkey_material_supported() {
    local algo="$1" key_file="" cert_file=""
    case "$algo" in
        *-cert-v01@openssh.com)
            cert_file="$(hostkey_certificate_required "$algo" 2>/dev/null || true)"
            [[ -n "$cert_file" && -f "$cert_file" ]] || return 1
            key_file="$(hostkey_private_file "$algo" 2>/dev/null || true)"
            [[ -f "$key_file" ]] || return 1
            ;;
    esac
    return 0
}

SSHD_KEX_ALGO_SUPPORT=""
sshd_supports_kex_algorithms() {
    # 是否存在 "KexAlgorithms" 配置项。
    #
    # 判据历史与现状：
    #   上游 OpenSSH 直到 6.1 才引入 "KexAlgorithms"；但 RHEL/CentOS 的 6.x
    #   打包版把它回溯移植到了 5.3p1 上（实测 CentOS 6.10 的 5.3p1：
    #   `sshd -t` 接受该指令，写假值会报 "Unsupported KEX algorithm"）。
    #   因此**不能只按主版本号猜测**——那会把 CentOS 6 误判成"不支持 KEX 锁定"，
    #   导致 5.3 上所有组合都不写 KexAlgorithms、KEX 断言被整段跳过。
    #
    # 现改为**运行时探测**：让 sshd 校验一个只含 KexAlgorithms 的最小配置。
    #   * 接受                                   → 支持（CentOS 6 回溯版、>=6.1）；
    #   * Bad configuration option / Unsupported → 不支持（真正的旧 5.x 上游版）。
    # 探测结果缓存到 SSHD_KEX_ALGO_SUPPORT，避免每项重复起进程。
    # 若 sshd 二进制不可用/无法探测，退回版本号判断（>=6 视为支持），保持旧行为。
    #
    # 探测值说明：这里填的是"指令是否被识别"的哨兵值，**与任何测试项的 KEX 无关**，
    # 也不会写进正式配置。因此刻意取一个**任何 OpenSSH 都不可能认得的假算法名**
    # （algo-probe-sentinel），而不是某个真实算法：
    #   * 若 sshd 认识 KexAlgorithms 指令 → 报 "Unsupported KEX algorithm ... sentinel"
    #     （属"指令被接受、只是值非法"）→ 判定支持；
    #   * 若 sshd 不认识该指令       → 报 "Bad configuration option ... KexAlgorithms"
    #     → 判定不支持。
    # 这样既不会因"某个真实算法被裁剪掉"而误判，也不会让人误以为脚本硬编码了 KEX。
    if [[ -n "$SSHD_KEX_ALGO_SUPPORT" ]]; then
        [[ "$SSHD_KEX_ALGO_SUPPORT" == "yes" ]]
        return
    fi
    if [[ -n "$SSHD_BIN" && -x "$SSHD_BIN" ]]; then
        local probe_tmp probe_out
        probe_tmp="$(mktemp "${TMP_DIR:-/tmp}/kexalgo_probe.XXXXXX" 2>/dev/null)" || probe_tmp=""
        if [[ -n "$probe_tmp" ]]; then
            printf '%s\n' 'Protocol 2' 'KexAlgorithms algo-probe-sentinel' > "$probe_tmp"
            probe_out="$("$SSHD_BIN" -t -f "$probe_tmp" 2>&1)"
            rm -f "$probe_tmp"
            # 判据精确化（关键）：
            #   * "Bad configuration option: KexAlgorithms" → 指令不存在 → 不支持；
            #   * "Unsupported KEX algorithm"（值非法）      → 指令存在   → 支持；
            #   * "Bad SSH2 KexAlgorithms '<值>'" (5.3 回溯版对非法值的措辞) → 指令存在 → 支持。
            # 注意：**不能**把 'Bad SSH2 KexAlgorithms' 也当作不支持——CentOS 6 的 5.3p1
            # 对"值非法"就是报这个，把两种情形混为一谈会导致误判。故只认
            # "Bad configuration option ... KexAlgorithms" 一种。
            if printf '%s' "$probe_out" |
                grep -qiE 'Bad configuration option.*KexAlgorithms|Unrecognized option.*KexAlgorithms'; then
                SSHD_KEX_ALGO_SUPPORT="no"
            else
                SSHD_KEX_ALGO_SUPPORT="yes"
            fi
            [[ "$SSHD_KEX_ALGO_SUPPORT" == "yes" ]]
            return
        fi
    fi
    # 无法探测：退回版本号。
    [[ -n "$SSHD_VER_MAJOR" ]] || return 0
    (( SSHD_VER_MAJOR >= 6 ))
}

append_probe_base_config() {
    # 探测配置必须与真实测试一致地隔离 Include/全局算法指令，避免原配置中的
    # Include 抢先提供旧算法而让预检产生假阴性。保留所有非算法认证/会话配置。
    local base="${BACKUP_FILE}"
    [[ -f "$base" ]] || base="$SSHD_CONFIG"
    awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; print; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1 }
        {
            if ($0 ~ /^[[:space:]]*(Protocol|KexAlgorithms|Ciphers|Cipher|MACs|HostKeyAlgorithms|HostKey|Include)[[:space:]]+/ ||
                (!in_match && $0 ~ /^[[:space:]]*(Port|ListenAddress|LogLevel|Compression)[[:space:]]+/)) {
                print "# UNIFIED_PROBE_COMMENTED: " $0
            } else {
                print
            }
        }
    ' "$base"
}

server_candidate_supported() {
    # 无副作用地验证"当前 sshd 是否能接受该算法组合"。不修改系统配置，
    # 不重启服务；真正测试阶段仍会再次执行 -t/-T。
    local kex="$1" cipher="$2" mac="$3" hostkey="$4" compression="${5:-}" proto="${6:-2}"
    local tmp out hostkey_file
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 2
    [[ "$proto" == "2" ]] || return 0

    if [[ "$hostkey" == *-cert-v01@openssh.com ]]; then
        server_hostkey_material_supported "$hostkey" || return 1
    fi

    hostkey_file="$(hostkey_private_file "$hostkey" 2>/dev/null || printf '%s\n' /etc/ssh/ssh_host_rsa_key)"

    tmp="$(mktemp "${TMP_DIR}/ssh_algo_probe.XXXXXX")" || return 2
    {
        printf '%s\n' '# SSH_ALGO_PROBE'
        printf '%s\n' 'Protocol 2'
        # KexAlgorithms 自 OpenSSH 6.1 才存在；5.x 写入会配置校验失败。
        if sshd_supports_kex_algorithms; then
            printf '%s\n' "KexAlgorithms $kex"
        fi
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
        case "$compression" in
            zlib@openssh.com) printf '%s\n' 'Compression delayed' ;;
            zlib) printf '%s\n' 'Compression yes' ;;
            none) printf '%s\n' 'Compression no' ;;
        esac
        append_probe_base_config
    } > "$tmp"

    if ! "$SSHD_BIN" -t -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"; return 1
    fi
    out="$("$SSHD_BIN" -T -f "$tmp" 2>/dev/null)" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"

    # 仅当该 sshd 支持 KexAlgorithms 时才校验 KEX 生效；5.x 无法固定 KEX，
    # 其 -T 也不输出 kexalgorithms，强行校验会把所有项误判为配置失败。
    if sshd_supports_kex_algorithms; then
        printf '%s\n' "$out" | awk '$1=="kexalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$kex" || return 1
    fi
    printf '%s\n' "$out" | awk '$1=="ciphers" {print $2}' | tr ',' '\n' | grep -qxF "$cipher" || return 1
    case "$compression" in
        none) printf '%s\n' "$out" | awk '$1=="compression" {print $2}' | grep -qxF "no" || return 1 ;;
        # sshd -T 会把 "Compression yes" 与 "Compression delayed" 都归一化成
        # "compression yes"（无法区分 zlib 与 zlib@openssh.com）。若这里要求
        # zlib@openssh.com 必须匹配 "delayed"，合法的延迟压缩组合会被误判为
        # 配置校验失败，导致整项被错误预检为 FAIL。
        # 反向兼容：OpenSSH < 6（CentOS 6 的 5.3）的 sshd -T 直接原样输出
        # "compression delayed"，并不像新版那样归一化成 "yes"。故 yes 与
        # delayed 都要接受，否则 5.x 上所有 zlib@openssh.com 组合会被预检误杀。
        zlib|zlib@openssh.com) printf '%s\n' "$out" | awk '$1=="compression" {print $2}' | grep -qxE 'yes|delayed' || return 1 ;;
        "") ;;
        *) return 1 ;;
    esac
    case "$cipher" in
        chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
        *) printf '%s\n' "$out" | awk '$1=="macs" {print $2}' | tr ',' '\n' | grep -qxF "$mac" || return 1 ;;
    esac

    if printf '%s\n' "$out" | awk '$1=="hostkeyalgorithms" {print $2}' | tr ',' '\n' | grep -qxF "$hostkey"; then
        return 0
    fi
    hostkey_file="$(hostkey_private_file "$hostkey" 2>/dev/null || true)"
    [[ -n "$hostkey_file" ]] || return 1
    printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -qxF "$hostkey_file"
}

mark_normal_coverage() {
    # 记录生成器已安排的计划 Coverage（仅 SSH-2 生成器据此做 uncovered 判定）。
    # 真实协商结果必须由 mark_actual_coverage 单独记录，不能反过来影响后续
    # 测试项生成。
    #
    # 说明：此处只维护 PLAN_COVERAGE_SEEN。早期版本另有一对只写不读的
    # SSH1_COVERAGE_SEEN/SSH2_COVERAGE_SEEN，经确认无任何读者（真实覆盖
    # 统计走 ACTUAL_SSH1/2_COVERAGE_SEEN，生成器决策走 PLAN_COVERAGE_SEEN），
    # 属遗留死代码，已移除。
    #
    # 注意：不能写 "local -n coverage" 后再 "coverage=PLAN_COVERAGE_SEEN"。
    # 不带 =target 的 local -n 创建的是"未绑定" nameref，向它赋值只是把
    # 字符串塞进 nameref 本身，随后 coverage["..."]=1 会在 set -u 下报
    # "coverage: unbound variable" 直接崩溃。这里直接操作目标关联数组。
    local proto="$1" kex="$2" cipher="$3" mac="$4" hostkey="$5" group="$6" compression="${7:-}"
    case "$proto" in
        1|2) ;;
        *) return 0 ;;
    esac
    [[ "$group" == *"NORMAL"* ]] || return 0

    # SSH-1 生成器不使用 PLAN_COVERAGE_SEEN 做决策；仅 SSH-2 需要登记。
    [[ "$proto" == "2" ]] || return 0

    PLAN_COVERAGE_SEEN["kex|$kex"]=1
    PLAN_COVERAGE_SEEN["cipher|$cipher"]=1
    PLAN_COVERAGE_SEEN["hostkey|$hostkey"]=1
    [[ -n "$compression" ]] && PLAN_COVERAGE_SEEN["compression|$compression"]=1

    case "$cipher" in
        chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
        *) [[ -n "$mac" ]] && PLAN_COVERAGE_SEEN["mac|$mac"]=1 ;;
    esac
}

mark_actual_coverage() {
    # 直接操作两个目标关联数组，不用 nameref 间接绑定：
    # 静态检查工具无法追踪 `local -n x=ARR` 后 x[...]=1 是在写关联数组，会误报
    # SC2178/SC2034；显式分支写具体数组名既消除误报，也让"写入哪个数组"一目了然。
    local proto="$1" kex="$2" cipher="$3" mac="$4" hostkey="$5" compression="${6:-}" nr="${7:-UNKNOWN}"
    [[ "$nr" == "PASS" ]] || return 0
    if [[ "$proto" == "2" ]]; then
        [[ -n "$kex" && "$kex" != "UNKNOWN" ]] &&
            ACTUAL_SSH2_COVERAGE_SEEN["kex|$kex"]=1
        [[ -n "$cipher" && "$cipher" != "UNKNOWN" ]] &&
            ACTUAL_SSH2_COVERAGE_SEEN["cipher|$cipher"]=1
        [[ -n "$hostkey" && "$hostkey" != "UNKNOWN" ]] &&
            ACTUAL_SSH2_COVERAGE_SEEN["hostkey|$hostkey"]=1
        [[ -n "$compression" && "$compression" != "UNKNOWN" ]] &&
            ACTUAL_SSH2_COVERAGE_SEEN["compression|$compression"]=1
        case "$cipher" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) [[ -n "$mac" && "$mac" != "UNKNOWN" ]] &&
                ACTUAL_SSH2_COVERAGE_SEEN["mac|$mac"]=1 ;;
        esac
    elif [[ "$proto" == "1" ]]; then
        [[ -n "$cipher" && "$cipher" != "UNKNOWN" ]] &&
            ACTUAL_SSH1_COVERAGE_SEEN["cipher|$cipher"]=1
        [[ -n "$compression" && "$compression" != "UNKNOWN" ]] &&
            ACTUAL_SSH1_COVERAGE_SEEN["compression|$compression"]=1
    fi
}

add_test() {
    local proto="$7" compression="${8:-}"

    # Compression 是完整 TEST_CASE 维度。每个 SSH 协议都同时保留关闭和
    # 开启压缩的物理组合；SSH-1 使用其实际 zlib 模型，而不是伪造 KEX/MAC。
    if [[ -z "$compression" ]]; then
        if [[ "$proto" == "2" ]]; then
            add_test "$@" "none"
            add_test "$@" "zlib@openssh.com"
        else
            add_test "$@" "none"
            add_test "$@" "zlib"
        fi
        return 0
    fi

    # 实际测试身份只由完整协商组合决定；NORMAL/SPECIAL 相同完整组合只测试一次，
    # 但合并所有语义标签，避免为同一个物理组合重复重启 sshd。
    local _dedup_key="${2}|${3}|${4}|${5}|${proto}|${compression}"
    if [[ -n "${GLOBAL_SEEN[$_dedup_key]:-}" ]]; then
        local _existing="${GLOBAL_SEEN[$_dedup_key]}"
        [[ "${TEST_GROUPS[$_existing]}" == *"$6"* ]] ||
            TEST_GROUPS[$_existing]="${TEST_GROUPS[$_existing]}|$6"
        [[ "${DESCS[$_existing]}" == *"$1"* ]] ||
            DESCS[$_existing]="${DESCS[$_existing]}; $1"
        # SPECIAL 与 NORMAL 物理组合仍只执行一次，但 NORMAL 语义必须
        # 获得自己的 coverage 名额，不能被先入的 SPECIAL 占用。
        mark_normal_coverage "$proto" "$2" "$3" "$4" "$5" "$6" "$compression"
        return 0
    fi

    # Worker 同时是客户端能力基准和安全排序基准；只做过滤，不改变其相对顺序。
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
    [[ "$6" == *"SERVER-FILTER"* ]] && SERVER_FILTERED_TESTS=$((SERVER_FILTERED_TESTS + 1))
    [[ "$6" == *"SERVER-FILTER/UNSUPPORTED"* ]] &&
        SERVER_UNSUPPORTED_TESTS=$((SERVER_UNSUPPORTED_TESTS + 1))
    [[ "$6" == *"SERVER-FILTER/UNKNOWN/PRECHECK_ERROR"* ]] &&
        SERVER_UNKNOWN_TESTS=$((SERVER_UNKNOWN_TESTS + 1))

    # 完整组合预检：明确 sshd 配置校验失败必须保留为 NEGOTIATION_FAIL，
    # 而不是从 TEST_CASE 中删除；探测不可用也保留为 UNKNOWN。
    local precheck_status="PASS"
    local precheck_reason=""
    local server_filter_class="NONE"
    [[ "$6" == *"SERVER-FILTER/UNSUPPORTED"* ]] &&
        server_filter_class="UNSUPPORTED"
    [[ "$6" == *"SERVER-FILTER/UNKNOWN/PRECHECK_ERROR"* ]] &&
        server_filter_class="UNKNOWN/PRECHECK_ERROR"
    if [[ "$7" == 2 ]]; then
        server_candidate_supported "$2" "$3" "$4" "$5" "$compression"
        local src=$?
        if (( src == 1 )); then
            precheck_status="FAIL"
            precheck_reason="服务器测试组合配置校验失败（sshd -t/-T）"
        elif (( src == 2 )); then
            precheck_status="UNKNOWN"
            precheck_reason="服务器组合预检不可用，保留并在真实测试阶段最终判定"
        fi
    fi
    case "$server_filter_class" in
        UNSUPPORTED)
            precheck_status="UNSUPPORTED"
            precheck_reason="Server Filter 判定为 UNSUPPORTED：服务器不支持该算法"
            ;;
        UNKNOWN/PRECHECK_ERROR)
            precheck_status="UNKNOWN"
            precheck_reason="Server Filter 判定为 UNKNOWN/PRECHECK_ERROR：服务器能力或预检不可确认"
            ;;
    esac

    local default_flag="n/a"
    if [[ "$7" == 2 ]] && $DEFAULT_CONFIG_LOADED; then
        local dk=false dc=false dm=false dh=false dz=false
        default_algorithm_supported kex "$2" && dk=true
        default_algorithm_supported cipher "$3" && dc=true
        case "$3" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                dm=true ;;
            *) default_algorithm_supported mac "$4" && dm=true ;;
        esac
        default_algorithm_supported hostkey "$5" && dh=true
        default_algorithm_supported compression "$compression" && dz=true
        if $dk && $dc && $dm && $dh && $dz; then
            default_flag="yes"
        else
            default_flag="no"
        fi
    fi

    GLOBAL_SEEN["$_dedup_key"]=$(( ${#DESCS[@]} ))
    DESCS+=("$1")
    KEXES+=("$2")
    CIPHERS+=("$3")
    MACS+=("$4")
    HOSTKEYS+=("$5")
    TEST_GROUPS+=("$6")
    PROTOCOLS+=("$7")
    COMPRESSIONS+=("${8:-}")
    DEFAULT_FLAGS+=("$default_flag")
    PRECHECK_STATUS+=("$precheck_status")
    PRECHECK_REASON+=("$precheck_reason")
    TEST_INDEX=$((TEST_INDEX + 1))
    mark_normal_coverage "$proto" "$2" "$3" "$4" "$5" "$6" "$compression"
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
    local tmp out hostkey_file probe_error probe_rc
    [[ -n "$SSHD_BIN" && -f "$SSHD_CONFIG" ]] || return 2
    [[ -n "$algo" ]] || return 0

    tmp="$(mktemp "${TMP_DIR}/ssh_algo_single.XXXXXX")" || return 2
    if ! {
        printf '%s\n' '# SSH_ALGO_SINGLE_PROBE'
        printf '%s\n' 'Protocol 2'
        case "$type" in
            kex)
                # 5.x 无 KexAlgorithms：无法通过配置探测单个 KEX 是否支持，
                # 返回 2（UNKNOWN）交由真实协商阶段判定，避免误报 UNSUPPORTED。
                if sshd_supports_kex_algorithms; then
                    printf '%s\n' "KexAlgorithms $algo"
                else
                    rm -f "$tmp"; return 2
                fi
                ;;
            cipher) printf '%s\n' "Ciphers $algo" ;;
            mac)    printf '%s\n' "MACs $algo" ;;
            hostkey)
                if [[ "$algo" == *-cert-v01@openssh.com ]]; then
                    server_hostkey_material_supported "$algo" || { rm -f "$tmp"; return 1; }
                fi
                hostkey_file="$(hostkey_private_file "$algo" 2>/dev/null || true)"
                [[ -n "$hostkey_file" ]] || { rm -f "$tmp"; return 1; }
                [[ -f "$hostkey_file" ]] || { rm -f "$tmp"; return 1; }
                printf '%s\n' "HostKey $hostkey_file"
                if [[ -n "$SSHD_VER_MAJOR" ]] && { (( SSHD_VER_MAJOR > 6 )) || { (( SSHD_VER_MAJOR == 6 )) && (( SSHD_VER_MINOR >= 5 )); }; }; then
                    printf '%s\n' "HostKeyAlgorithms $algo"
                fi
                ;;
        esac
        append_probe_base_config
    } > "$tmp"; then
        rm -f "$tmp"
        return 2
    fi

    probe_error="$("$SSHD_BIN" -t -f "$tmp" 2>&1)"
    probe_rc=$?
    if (( probe_rc != 0 )); then
        rm -f "$tmp"
        # "Bad key types 'x'." 是 HostKeyAlgorithms 填写了 sshd 不认识的名字时
        # 的报错（例如 openEuler 的真实名字是 sm2，而 Worker 侧沿用了 ssh-sm2
        # 这种 ssh-rsa/ssh-dss 风格的旧命名）。必须归入 UNSUPPORTED，否则会被
        # 当成 PRECHECK_ERROR（UNKNOWN）掩盖真实的"服务器不支持该算法名"事实。
        if printf '%s\n' "$probe_error" |
            grep -qiE 'bad (ssh2 )?(kex|cipher|mac|host key|hostkey|key types?)|unknown (algorithm|cipher|kex|mac|host key|hostkey)|unsupported|invalid.*(algorithm|cipher|kex|mac|host key|hostkey)|no matching'; then
            return 1
        fi
        return 2
    fi
    out="$("$SSHD_BIN" -T -f "$tmp" 2>/dev/null)" || { rm -f "$tmp"; return 2; }
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
            [[ -n "$hostkey_file" ]] &&
                printf '%s\n' "$out" | awk '$1=="hostkey" {print $2}' | grep -qxF "$hostkey_file"
            ;;
        *) return 2 ;;
    esac
}

server_filter_status() {
    local type="$1" algo="$2" rc
    server_algo_supported "$type" "$algo"
    rc=$?
    case "$rc" in
        0) printf '%s\n' SUPPORTED ;;
        1) printf '%s\n' UNSUPPORTED ;;
        *) printf '%s\n' UNKNOWN ;;
    esac
}

normal_try_add() {
    local desc="$1" kex="$2" cipher="$3" mac="$4" hostkey="$5" group="$6"
    local compression="${7:-}"
    if [[ -n "$compression" ]]; then
        add_test "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$group" 2 "$compression"
        [[ -n "${GLOBAL_SEEN["${kex}|${cipher}|${mac}|${hostkey}|2|${compression}"]:-}" ]]
    else
        add_test "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$group" 2
        [[ -n "${GLOBAL_SEEN["${kex}|${cipher}|${mac}|${hostkey}|2|none"]:-}" ||
           -n "${GLOBAL_SEEN["${kex}|${cipher}|${mac}|${hostkey}|2|zlib@openssh.com"]:-}" ]]
    fi
}

repair_normal_coverage() {
    # SPECIAL 只负责自身语义；SPECIAL 与 NORMAL 物理组合去重时，SPECIAL 不能
    # 占用 NORMAL 的覆盖名额。这里寻找尚未执行的替代完整组合，补齐 NORMAL 缺口。
    local lc=${#NORMAL_CANDIDATE_CIPHER[@]}
    local lm=${#NORMAL_CANDIDATE_MAC[@]}
    local lk=${#NORMAL_CANDIDATE_KEX[@]}
    local lh=${#NORMAL_CANDIDATE_HOSTKEY[@]}
    local lz=${#NORMAL_CANDIDATE_COMPRESSION[@]}
    local first_non_aead="" c m h k desc
    local ki ci mi hi added

    for c in "${NORMAL_CANDIDATE_CIPHER[@]}"; do
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) first_non_aead="$c"; break ;;
        esac
    done

    # 每个缺失 KEX 至少生成一个新的、完整的 NORMAL 组合。
    for k in "${NORMAL_CANDIDATE_KEX[@]}"; do
        [[ -n "${PLAN_COVERAGE_SEEN["kex|$k"]:-}" ]] && continue
        added=0
        for ((ci=0; ci<lc && added == 0; ci++)); do
            c="${NORMAL_CANDIDATE_CIPHER[$ci]}"
            for ((hi=0; hi<lh && added == 0; hi++)); do
                h="${NORMAL_CANDIDATE_HOSTKEY[$hi]}"
                if [[ "$c" =~ ^(chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)$ ]]; then
                    m=""
                    desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=NONE hostkey=$h"
                    normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                else
                    for ((mi=0; mi<lm && added == 0; mi++)); do
                        m="${NORMAL_CANDIDATE_MAC[$mi]}"
                        desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=$m hostkey=$h"
                        normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                    done
                fi
            done
        done
    done

    # 每个缺失 Cipher 至少生成一个新的 NORMAL 组合。
    for c in "${NORMAL_CANDIDATE_CIPHER[@]}"; do
        [[ -n "${PLAN_COVERAGE_SEEN["cipher|$c"]:-}" ]] && continue
        [[ "$lc" -gt 0 ]] || continue
        added=0
        for ((ki=0; ki<lk && added == 0; ki++)); do
            k="${NORMAL_CANDIDATE_KEX[$ki]}"
            for ((hi=0; hi<lh && added == 0; hi++)); do
                h="${NORMAL_CANDIDATE_HOSTKEY[$hi]}"
                if [[ "$c" =~ ^(chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)$ ]]; then
                    m=""
                    desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=NONE hostkey=$h"
                    normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                else
                    for ((mi=0; mi<lm && added == 0; mi++)); do
                        m="${NORMAL_CANDIDATE_MAC[$mi]}"
                        desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=$m hostkey=$h"
                        normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                    done
                fi
            done
        done
    done

    # 每个缺失 HostKey 至少生成一个新的 NORMAL 组合。
    for h in "${NORMAL_CANDIDATE_HOSTKEY[@]}"; do
        [[ -n "${PLAN_COVERAGE_SEEN["hostkey|$h"]:-}" ]] && continue
        added=0
        for ((ki=0; ki<lk && added == 0; ki++)); do
            k="${NORMAL_CANDIDATE_KEX[$ki]}"
            for ((ci=0; ci<lc && added == 0; ci++)); do
                c="${NORMAL_CANDIDATE_CIPHER[$ci]}"
                if [[ "$c" =~ ^(chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)$ ]]; then
                    m=""
                    desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=NONE hostkey=$h"
                    normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                else
                    for ((mi=0; mi<lm && added == 0; mi++)); do
                        m="${NORMAL_CANDIDATE_MAC[$mi]}"
                        desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=$m hostkey=$h"
                        normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐" && added=1
                    done
                fi
            done
        done
    done

    # 每个缺失 MAC 必须使用非 AEAD Cipher，使该 MAC 真正参与 SSH 协商。
    if [[ -n "$first_non_aead" ]]; then
        for m in "${NORMAL_CANDIDATE_MAC[@]}"; do
            [[ -n "${PLAN_COVERAGE_SEEN["mac|$m"]:-}" ]] && continue
            added=0
            for ((ki=0; ki<lk && added == 0; ki++)); do
                k="${NORMAL_CANDIDATE_KEX[$ki]}"
                for ((hi=0; hi<lh && added == 0; hi++)); do
                    h="${NORMAL_CANDIDATE_HOSTKEY[$hi]}"
                    desc="NORMAL覆盖补齐: kex=$k cipher=$first_non_aead mac=$m hostkey=$h"
                    normal_try_add "$desc" "$k" "$first_non_aead" "$m" "$h" "NORMAL/覆盖补齐/MAC" && added=1
                done
            done
        done
    fi

    # Compression 也是 SSH-2 NORMAL 的独立覆盖维度；按 TEST_CASE 的
    # 实际值补齐 none 与 zlib@openssh.com，不能只依赖其它维度的轮转。
    if (( lz > 0 )); then
        for z in "${NORMAL_CANDIDATE_COMPRESSION[@]}"; do
            [[ -n "${PLAN_COVERAGE_SEEN["compression|$z"]:-}" ]] && continue
            added=0
            k="${NORMAL_CANDIDATE_KEX[0]:-}"
            c="${NORMAL_CANDIDATE_CIPHER[0]:-}"
            h="${NORMAL_CANDIDATE_HOSTKEY[0]:-}"
            m="${NORMAL_CANDIDATE_MAC[0]:-}"
            [[ "$c" =~ ^(chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)$ ]] && m=""
            if [[ -n "$k$c$h" ]]; then
                desc="NORMAL覆盖补齐: kex=$k cipher=$c mac=${m:-NONE} hostkey=$h compression=$z"
                normal_try_add "$desc" "$k" "$c" "$m" "$h" "NORMAL/覆盖补齐/Compression" "$z" && added=1
            fi
        done
    fi
}

load_dynamic_tests() {
    # 五维 coverage-driven 生成：每次优先把尚未覆盖的 KEX/Cipher/MAC/
    # HostKey/Compression 放入同一个完整组合，而不是按索引轮转或生成笛卡尔积。
    # Worker 顺序只决定候选值的优先级；AEAD 仍保持 MAC=N/A。
    local kex_c=() ciph_c=() mac_c=() hk_c=() algo
    local rejected_kex=() rejected_cipher=() rejected_mac=() rejected_hostkey=()
    local unknown_kex=() unknown_cipher=() unknown_mac=() unknown_hostkey=()
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status kex "$algo")" in
            SUPPORTED) kex_c+=("$algo") ;;
            UNSUPPORTED) rejected_kex+=("$algo") ;;
            *) unknown_kex+=("$algo") ;;
        esac
    done <<< "$WORKER_KEX"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status cipher "$algo")" in
            SUPPORTED) ciph_c+=("$algo") ;;
            UNSUPPORTED) rejected_cipher+=("$algo") ;;
            *) unknown_cipher+=("$algo") ;;
        esac
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status mac "$algo")" in
            SUPPORTED) mac_c+=("$algo") ;;
            UNSUPPORTED) rejected_mac+=("$algo") ;;
            *) unknown_mac+=("$algo") ;;
        esac
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status hostkey "$algo")" in
            SUPPORTED) hk_c+=("$algo") ;;
            UNSUPPORTED)
                [[ "$algo" == *-cert-v01@openssh.com ]] &&
                    env_log "过滤 HostKey certificate（缺少对应私钥/证书材料）: $algo"
                rejected_hostkey+=("$algo") ;;
            *) unknown_hostkey+=("$algo") ;;
        esac
    done <<< "$WORKER_HOSTKEYS"

    local lk=${#kex_c[@]} lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    # server-filter 失败也是可审计的 TEST_CASE，不能静默丢弃。每个被过滤的
    # Worker 算法用其余维度的第一个基线算法形成一个明确失败的代表组合。
    local fallback_kex="${kex_c[0]:-}" fallback_cipher="${ciph_c[0]:-}"
    local fallback_mac="${mac_c[0]:-}" fallback_hostkey="${hk_c[0]:-}"
    local fallback_cipher_for_mac="$fallback_cipher"
    for algo in "${ciph_c[@]}"; do
        case "$algo" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) fallback_cipher_for_mac="$algo"; break ;;
        esac
    done
    [[ -n "$fallback_kex" ]] || fallback_kex="$(printf '%s\n' "$WORKER_KEX" | head -1)"
    [[ -n "$fallback_cipher" ]] || fallback_cipher="$(printf '%s\n' "$WORKER_CIPHERS" | head -1)"
    [[ -n "$fallback_cipher_for_mac" ]] || fallback_cipher_for_mac="$fallback_cipher"
    [[ -n "$fallback_mac" ]] || fallback_mac="$(printf '%s\n' "$WORKER_MACS" | head -1)"
    [[ -n "$fallback_hostkey" ]] || fallback_hostkey="$(printf '%s\n' "$WORKER_HOSTKEYS" | head -1)"
    for algo in "${rejected_kex[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: kex=$algo" "$algo" "$fallback_cipher" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_cipher[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: cipher=$algo" "$fallback_kex" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_mac[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: mac=$algo" "$fallback_kex" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_hostkey[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: hostkey=$algo" "$fallback_kex" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${unknown_kex[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: kex=$algo" "$algo" "$fallback_cipher" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_cipher[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: cipher=$algo" "$fallback_kex" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_mac[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: mac=$algo" "$fallback_kex" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_hostkey[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: hostkey=$algo" "$fallback_kex" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done

    (( lk > 0 && lc > 0 && lh > 0 )) || return 0
    local i k c m h z other_z
    local first_non_aead=""
    for c in "${ciph_c[@]}"; do
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) first_non_aead="$c"; break ;;
        esac
    done

    # 以 coverage 状态为决策输入：一个组合尽量同时承载每个维度当前
    # 的第一个未覆盖值；下一轮重新读取 coverage，而不是使用索引取模。
    while :; do
        k="${kex_c[0]:-}"
        c="${ciph_c[0]:-}"
        m="${mac_c[0]:-}"
        h="${hk_c[0]:-}"
        z=""
        for ((i=0; i<lk; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["kex|${kex_c[$i]}"]:-}" ]] || { k="${kex_c[$i]}"; break; }
        done
        for ((i=0; i<lc; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] || { c="${ciph_c[$i]}"; break; }
        done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do
                [[ -n "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] || { m="${mac_c[$i]}"; break; }
            done
        fi
        for ((i=0; i<lh; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] || { h="${hk_c[$i]}"; break; }
        done
        for z in none zlib@openssh.com; do
            [[ -n "${PLAN_COVERAGE_SEEN["compression|$z"]:-}" ]] || break
            z=""
        done

        # No uncovered value remains.  Compression is selected from the same
        # coverage state as the algorithm dimensions.
        [[ -z "$k" || -z "$c" || -z "$h" ]] && break
        local uncovered=false
        for ((i=0; i<lk; i++)); do
            [[ -z "${PLAN_COVERAGE_SEEN["kex|${kex_c[$i]}"]:-}" ]] && uncovered=true
        done
        for ((i=0; i<lc; i++)); do
            [[ -z "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] && uncovered=true
        done
        for ((i=0; i<lh; i++)); do
            [[ -z "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] && uncovered=true
        done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do
                [[ -z "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] && uncovered=true
            done
        fi
        [[ -n "$z" ]] && uncovered=true
        [[ "$uncovered" == true ]] || break

        # AEAD 不能携带传统 MAC；当目标是未覆盖 MAC 时固定非 AEAD Cipher。
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                [[ -n "$first_non_aead" && -z "${PLAN_COVERAGE_SEEN["mac|$m"]:-}" ]] && c="$first_non_aead"
                ;;
        esac
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        if [[ -n "$z" ]]; then
            add_test "组合(coverage-driven): kex=$k cipher=$c mac=${m:-NONE} hostkey=$h compression=$z" \
                "$k" "$c" "$m" "$h" "动态/NORMAL/五维覆盖" 2 "$z"
            for other_z in none zlib@openssh.com; do
                [[ "$other_z" == "$z" ]] && continue
                [[ -n "${PLAN_COVERAGE_SEEN["compression|$other_z"]:-}" ]] && continue
                add_test "组合(coverage-driven): kex=$k cipher=$c mac=${m:-NONE} hostkey=$h compression=$other_z" \
                    "$k" "$c" "$m" "$h" "动态/NORMAL/五维覆盖" 2 "$other_z"
            done
        else
            add_test "组合(coverage-driven): kex=$k cipher=$c mac=${m:-NONE} hostkey=$h" \
                "$k" "$c" "$m" "$h" "动态/NORMAL/五维覆盖" 2
        fi
    done
    NORMAL_CANDIDATE_KEX=("${kex_c[@]}")
    NORMAL_CANDIDATE_CIPHER=("${ciph_c[@]}")
    NORMAL_CANDIDATE_MAC=("${mac_c[@]}")
    NORMAL_CANDIDATE_HOSTKEY=("${hk_c[@]}")
    NORMAL_CANDIDATE_COMPRESSION=(none zlib@openssh.com)
    repair_normal_coverage
}

# ============================================================
# 原 test_centos6.sh：实际启用的 test_algo 项
# ============================================================
#
# 说明（为何要按 server_filter_status 逐维过滤）：
#   本 profile 的候选列表是「CentOS 6 / OpenSSH 5.3 的目标测试集合」，其中
#   包含若干该版本并不具备的算法（如 3des-ctr —— 5.3 只有 3des-cbc，没有
#   任何 *-ctr 的 3DES；hmac-ripemd160-etm@openssh.com —— -etm 变体自 6.2 才有）。
#   若直接把整条组合交给 add_test，add_test 内部的组合预检会因 sshd -t 失败
#   把它记成 precheck FAIL（"服务器测试组合配置校验失败"），语义上等同于
#   "被测服务器有问题"，掩盖了真正的原因——该算法本就不被该版本支持。
#
#   这里改为与 openssh8 profile 一致的做法：先用 server_filter_status 逐维判定
#   服务器是否支持该算法，明确不支持的记为 SERVER-FILTER/UNSUPPORTED（这是
#   期望的负结果，可审计且不计入异常失败），能力无法确认的记为
#   SERVER-FILTER/UNKNOWN/PRECHECK_ERROR，只有真正支持的才作为普通测试项。
centos6_add() {
    local desc="$1" kex="$2" cipher="$3" mac="$4" hostkey="$5" group="$6" compression="${7:-}"
    local s kind=""

    # 逐维检查服务端支持性。判定规则：
    #   * 任一维度明确 UNSUPPORTED  => 整条组合记为 SERVER-FILTER/UNSUPPORTED
    #     （期望的负结果，可审计，不是异常失败）；
    #   * 否则一律作为普通测试项交给 add_test，由其中的"完整组合预检"
    #     （server_candidate_supported）决定最终分类。
    #
    # 注意：这里刻意不把 UNKNOWN 升级为 SERVER-FILTER 测试。某些旧 sshd
    # 既无 KexAlgorithms 也无对应 -T 字段，KEX 维度无法用配置探测、必然返回
    # UNKNOWN——那是"该维度不可探测"而非"组合能力存疑"。若据此降级，每条
    # 组合都会变成 UNKNOWN/PRECHECK_ERROR，反而丢失 ciphers/macs/hostkey 上
    # 真正可判定的结论。故仅在 sshd 真能锁定 KEX 时才做 KEX 维度过滤。
    local s
    if sshd_supports_kex_algorithms && [[ "$(server_filter_status kex "$kex")" == "UNSUPPORTED" ]]; then
        kind="UNSUPPORTED"
    else
        for s in \
            "$(server_filter_status cipher "$cipher")" \
            "$(server_filter_status mac "$mac")" \
            "$(server_filter_status hostkey "$hostkey")"; do
            if [[ "$s" == "UNSUPPORTED" ]]; then
                kind="UNSUPPORTED"
                break
            fi
        done
    fi

    # 关键：调用 add_test 时，只有当 compression 非空才传第 8 个实参。
    # add_test 的约定是「第 8 参缺省 => 该组合需要展开出 none / zlib 两个物理
    # 组合」。若在此处把空串作为第 8 参显式传入，add_test 内部的展开逻辑
    # （add_test "$@" "none"）会把空串当成已有的第 8 参、再把 "none" 追加为
    # 第 9 参，导致第 8 参永远是空串而无限递归（表现为段错误/爆栈）。
    if [[ "$kind" == "UNSUPPORTED" ]]; then
        env_log "SERVER-FILTER：$desc 含服务器不支持的算法，记为 UNSUPPORTED"
        if [[ -n "$compression" ]]; then
            add_test "SERVER-FILTER UNSUPPORTED: $desc" \
                "$kex" "$cipher" "$mac" "$hostkey" "SERVER-FILTER/UNSUPPORTED" 2 "$compression"
        else
            add_test "SERVER-FILTER UNSUPPORTED: $desc" \
                "$kex" "$cipher" "$mac" "$hostkey" "SERVER-FILTER/UNSUPPORTED" 2
        fi
        return 0
    fi
    if [[ -n "$compression" ]]; then
        add_test "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$group" 2 "$compression"
    else
        add_test "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$group" 2
    fi
}

load_centos6_tests() {
    centos6_add "blowfish-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "cast128-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "cast128-cbc" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "arcfour + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "arcfour256 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour256" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "arcfour128 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour128" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "rijndael-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "rijndael-cbc@lysator.liu.se" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "3des-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "3des-ctr + hmac-sha1" \
        "diffie-hellman-group14-sha1" "3des-ctr" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "aes256-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes256-cbc" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "aes128-ctr + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes128-ctr" "hmac-sha1" "ssh-rsa" "Cipher"
    centos6_add "aes256-ctr + hmac-md5" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5" "ssh-rsa" "MAC"
    centos6_add "aes256-ctr + hmac-md5-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5-96" "ssh-rsa" "MAC"
    centos6_add "aes256-ctr + hmac-sha1-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-sha1-96" "ssh-rsa" "MAC"
    centos6_add "aes256-ctr + hmac-ripemd160" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160" "ssh-rsa" "MAC"
    centos6_add "aes256-ctr + hmac-ripemd160-etm" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160-etm@openssh.com" "ssh-rsa" "MAC"
    centos6_add "aes256-ctr + hmac-ripemd160@openssh.com" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160@openssh.com" "ssh-rsa" "MAC"

    centos6_add "ssh-dss + 3des-cbc + hmac-md5" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-md5" "ssh-dss" "HostKey"
    centos6_add "ssh-dss + blowfish + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "ssh-dss" "HostKey"
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
    # 正常情形：-T 直接给出 protocol 值（如 "2" 或 "1,2" 拆成 "1"/"2"）。
    if printf '%s\n' "$out" | grep -qx "1"; then
        return 0
    fi
    # 旧版 OpenSSH（如 CentOS 6 的 5.3p1）的 sshd -T 对"含 Protocol 1 的组合"
    # 一律显示 "protocol UNKNOWN"（其 -T 只认 2）。此时不能据此判假，否则
    # 明明支持 SSH-1 的机器会被整段跳过 SSH-1 用例。故回退解析原始配置文件的
    # Protocol 指令：含 "1"（如 "Protocol 1" 或 "Protocol 1,2"）即视为含 1。
    # 注意：仅当 -T 明确"没给出 2"（即 UNKNOWN/空）时才回退，避免与正常路径冲突。
    if printf '%s\n' "$out" | grep -qx "UNKNOWN" || [[ -z "$out" ]]; then
        local proto_line
        proto_line="$(
            awk '
                /^[[:space:]]*[Pp][Rr][Oo][Tt][Oo][Cc][Oo][Ll][[:space:]]/ {
                    sub(/^[[:space:]]*[Pp][Rr][Oo][Tt][Oo][Cc][Oo][Ll][[:space:]]+/, "");
                    gsub(/[[:space:]]/, "");
                    print; exit
                }
            ' "$SSHD_CONFIG" 2>/dev/null
        )"
        printf '%s\n' "$proto_line" | tr ',' '\n' | grep -qx "1" && return 0
    fi
    return 1
}

ssh1_binary_supported() {
    [[ -n "$SSHD_BIN" ]] || return 1
    local tmp keytmp
    tmp="$(mktemp "${TMP_DIR}/ssh1probe.XXXXXX" 2>/dev/null)" || return 1
    keytmp="$(mktemp "${TMP_DIR}/ssh1probe_key.XXXXXX" 2>/dev/null)" || {
        rm -f "$tmp"
        return 1
    }
    rm -f "$keytmp" "$keytmp.pub"
    if ! ssh-keygen -q -t rsa1 -b 1024 -f "$keytmp" -N "" >/dev/null 2>&1 ||
       [[ ! -s "$keytmp" ]]; then
        rm -f "$tmp" "$keytmp" "$keytmp.pub"
        return 1
    fi
    {
        printf '%s\n' '# SSH1_PROBE'
        printf '%s\n' 'Protocol 1'
        printf '%s\n' "HostKey $keytmp"
        printf '%s\n' 'PasswordAuthentication yes'
    } > "$tmp"
    if "$SSHD_BIN" -t -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp" "$keytmp" "$keytmp.pub"
        return 0
    fi
    rm -f "$tmp" "$keytmp" "$keytmp.pub"
    return 1
}

# ============================================================
# 原 test_openssh8.sh：实际启用的 1 项
# ============================================================
load_openssh8_tests() {
    # X448 固定为 KEX；只有服务器实际可配置/可验证时才进入最终测试集。
    case "$(server_filter_status kex "curve448-sha512")" in
      UNSUPPORTED)
        add_test "SERVER-FILTER UNSUPPORTED: kex=curve448-sha512" "curve448-sha512" \
            "$(printf '%s\n' "$WORKER_CIPHERS" | head -1)" \
            "$(printf '%s\n' "$WORKER_MACS" | head -1)" \
            "$(printf '%s\n' "$WORKER_HOSTKEYS" | head -1)" \
            "SERVER-FILTER/UNSUPPORTED" 2
        return 0
        ;;
      UNKNOWN)
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: kex=curve448-sha512" "curve448-sha512" \
            "$(printf '%s\n' "$WORKER_CIPHERS" | head -1)" \
            "$(printf '%s\n' "$WORKER_MACS" | head -1)" \
            "$(printf '%s\n' "$WORKER_HOSTKEYS" | head -1)" \
            "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
        return 0
        ;;
    esac
    local ciph_c=() mac_c=() hk_c=() algo
    local rejected_cipher=() rejected_mac=() rejected_hostkey=()
    local unknown_cipher=() unknown_mac=() unknown_hostkey=()
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status cipher "$algo")" in
            SUPPORTED) ciph_c+=("$algo") ;;
            UNSUPPORTED) rejected_cipher+=("$algo") ;;
            *) unknown_cipher+=("$algo") ;;
        esac
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status mac "$algo")" in
            SUPPORTED) mac_c+=("$algo") ;;
            UNSUPPORTED) rejected_mac+=("$algo") ;;
            *) unknown_mac+=("$algo") ;;
        esac
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status hostkey "$algo")" in
            SUPPORTED) hk_c+=("$algo") ;;
            UNSUPPORTED)
                [[ "$algo" == *-cert-v01@openssh.com ]] &&
                    env_log "过滤 HostKey certificate（缺少对应私钥/证书材料）: $algo"
                rejected_hostkey+=("$algo") ;;
            *) unknown_hostkey+=("$algo") ;;
        esac
    done <<< "$WORKER_HOSTKEYS"

    local fallback_cipher="${ciph_c[0]:-}" fallback_mac="${mac_c[0]:-}" fallback_hostkey="${hk_c[0]:-}"
    local fallback_cipher_for_mac="$fallback_cipher"
    for algo in "${ciph_c[@]}"; do
        case "$algo" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) fallback_cipher_for_mac="$algo"; break ;;
        esac
    done
    [[ -n "$fallback_cipher" ]] || fallback_cipher="$(printf '%s\n' "$WORKER_CIPHERS" | head -1)"
    [[ -n "$fallback_cipher_for_mac" ]] || fallback_cipher_for_mac="$fallback_cipher"
    [[ -n "$fallback_mac" ]] || fallback_mac="$(printf '%s\n' "$WORKER_MACS" | head -1)"
    [[ -n "$fallback_hostkey" ]] || fallback_hostkey="$(printf '%s\n' "$WORKER_HOSTKEYS" | head -1)"
    for algo in "${rejected_cipher[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: cipher=$algo" "curve448-sha512" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_mac[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: mac=$algo" "curve448-sha512" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_hostkey[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: hostkey=$algo" "curve448-sha512" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${unknown_cipher[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: cipher=$algo" "curve448-sha512" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_mac[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: mac=$algo" "curve448-sha512" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_hostkey[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: hostkey=$algo" "curve448-sha512" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    local lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    (( lc > 0 && lh > 0 )) || return 0
    local i c m h z other_z first_non_aead=""
    for c in "${ciph_c[@]}"; do
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) first_non_aead="$c"; break ;;
        esac
    done
    while :; do
        c="${ciph_c[0]:-}"
        m="${mac_c[0]:-}"
        h="${hk_c[0]:-}"
        z=""
        for ((i=0; i<lc; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] || { c="${ciph_c[$i]}"; break; }
        done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do
                [[ -n "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] || { m="${mac_c[$i]}"; break; }
            done
        fi
        for ((i=0; i<lh; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] || { h="${hk_c[$i]}"; break; }
        done
        for z in none zlib@openssh.com; do
            [[ -n "${PLAN_COVERAGE_SEEN["compression|$z"]:-}" ]] || break
            z=""
        done
        local uncovered=false
        for ((i=0; i<lc; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] && uncovered=true; done
        for ((i=0; i<lh; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] && uncovered=true; done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] && uncovered=true; done
        fi
        [[ -n "$z" ]] && uncovered=true
        [[ "$uncovered" == true ]] || break
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                [[ -n "$first_non_aead" && -z "${PLAN_COVERAGE_SEEN["mac|$m"]:-}" ]] && c="$first_non_aead" ;;
        esac
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        if [[ -n "$z" ]]; then
            add_test "OpenSSH8 X448 coverage-driven: kex=curve448-sha512 cipher=$c mac=${m:-NONE} hostkey=$h compression=$z" \
                "curve448-sha512" "$c" "$m" "$h" "OpenSSH8/X448/NORMAL" 2 "$z"
            for other_z in none zlib@openssh.com; do
                [[ "$other_z" == "$z" || -n "${PLAN_COVERAGE_SEEN["compression|$other_z"]:-}" ]] && continue
                add_test "OpenSSH8 X448 coverage-driven: kex=curve448-sha512 cipher=$c mac=${m:-NONE} hostkey=$h compression=$other_z" \
                    "curve448-sha512" "$c" "$m" "$h" "OpenSSH8/X448/NORMAL" 2 "$other_z"
            done
        else
            add_test "OpenSSH8 X448 coverage-driven: kex=curve448-sha512 cipher=$c mac=${m:-NONE} hostkey=$h" \
                "curve448-sha512" "$c" "$m" "$h" "OpenSSH8/X448/NORMAL" 2
        fi
    done
    # X448 专项也必须完成其自身 NORMAL 的 Cipher/MAC/HostKey 覆盖；KEX 已固定为 X448。
    NORMAL_CANDIDATE_KEX=("curve448-sha512")
    NORMAL_CANDIDATE_CIPHER=("${ciph_c[@]}")
    NORMAL_CANDIDATE_MAC=("${mac_c[@]}")
    NORMAL_CANDIDATE_HOSTKEY=("${hk_c[@]}")
    NORMAL_CANDIDATE_COMPRESSION=(none zlib@openssh.com)
    repair_normal_coverage
}

# ============================================================
# openEuler 国密算法测试
# ============================================================
load_openeuler_tests() {
    fallback_cipher_for_mac=""
    local _worker_cipher
    while IFS= read -r _worker_cipher; do
        case "$_worker_cipher" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) fallback_cipher_for_mac="$_worker_cipher"; break ;;
        esac
    done <<< "$WORKER_CIPHERS"
    [[ -n "$fallback_cipher_for_mac" ]] || fallback_cipher_for_mac="$(printf '%s\n' "$WORKER_CIPHERS" | head -1)"
    # SPECIAL：国密全链路独立存在；与 NORMAL 完全相同的物理组合只执行一次。
    # HostKey 必须用 openEuler 真实算法名 sm2。openEuler 的 ssh -Q key /
    # ssh -Q HostKeyAlgorithms 只认 "sm2"（以及 "sm2-cert"），"ssh-sm2" 会被
    # sshd 拒绝为 "Bad key types"，客户端也无法协商成功——沿用 Worker 内部
    # 的 ssh-sm2 命名会让这条全链路用例永远失败。
    add_test "国密全链路: sm2-sm3 + sm4-ctr + hmac-sm3 + sm2" \
        "sm2-sm3" "sm4-ctr" "hmac-sm3" "sm2" "国密/SPECIAL/全链路" 2

    # NORMAL 单独完成五维 Worker/Server 覆盖；SPECIAL 不代替 NORMAL。
    local kex_c=() ciph_c=() mac_c=() hk_c=() algo
    local rejected_kex=() rejected_cipher=() rejected_mac=() rejected_hostkey=()
    local unknown_kex=() unknown_cipher=() unknown_mac=() unknown_hostkey=()
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status kex "$algo")" in
            SUPPORTED) kex_c+=("$algo") ;;
            UNSUPPORTED) rejected_kex+=("$algo") ;;
            *) unknown_kex+=("$algo") ;;
        esac
    done <<< "$WORKER_KEX"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status cipher "$algo")" in
            SUPPORTED) ciph_c+=("$algo") ;;
            UNSUPPORTED) rejected_cipher+=("$algo") ;;
            *) unknown_cipher+=("$algo") ;;
        esac
    done <<< "$WORKER_CIPHERS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status mac "$algo")" in
            SUPPORTED) mac_c+=("$algo") ;;
            UNSUPPORTED) rejected_mac+=("$algo") ;;
            *) unknown_mac+=("$algo") ;;
        esac
    done <<< "$WORKER_MACS"
    while IFS= read -r algo; do
        [[ -n "$algo" ]] || continue
        case "$(server_filter_status hostkey "$algo")" in
            SUPPORTED) hk_c+=("$algo") ;;
            UNSUPPORTED)
                [[ "$algo" == *-cert-v01@openssh.com ]] &&
                    env_log "过滤 HostKey certificate（缺少对应私钥/证书材料）: $algo"
                rejected_hostkey+=("$algo") ;;
            *) unknown_hostkey+=("$algo") ;;
        esac
    done <<< "$WORKER_HOSTKEYS"

    local fallback_kex="${kex_c[0]:-}" fallback_cipher="${ciph_c[0]:-}"
    local fallback_mac="${mac_c[0]:-}" fallback_hostkey="${hk_c[0]:-}"
    [[ -n "$fallback_kex" ]] || fallback_kex="$(printf '%s\n' "$WORKER_KEX" | head -1)"
    [[ -n "$fallback_cipher" ]] || fallback_cipher="$(printf '%s\n' "$WORKER_CIPHERS" | head -1)"
    [[ -n "$fallback_mac" ]] || fallback_mac="$(printf '%s\n' "$WORKER_MACS" | head -1)"
    [[ -n "$fallback_hostkey" ]] || fallback_hostkey="$(printf '%s\n' "$WORKER_HOSTKEYS" | head -1)"
    for algo in "${rejected_kex[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: kex=$algo" "$algo" "$fallback_cipher" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_cipher[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: cipher=$algo" "$fallback_kex" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_mac[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: mac=$algo" "$fallback_kex" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${rejected_hostkey[@]}"; do
        add_test "SERVER-FILTER UNSUPPORTED: hostkey=$algo" "$fallback_kex" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNSUPPORTED" 2
    done
    for algo in "${unknown_kex[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: kex=$algo" "$algo" "$fallback_cipher" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_cipher[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: cipher=$algo" "$fallback_kex" "$algo" "$fallback_mac" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_mac[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: mac=$algo" "$fallback_kex" "$fallback_cipher_for_mac" "$algo" "$fallback_hostkey" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    for algo in "${unknown_hostkey[@]}"; do
        add_test "SERVER-FILTER UNKNOWN/PRECHECK_ERROR: hostkey=$algo" "$fallback_kex" "$fallback_cipher" "$fallback_mac" "$algo" "SERVER-FILTER/UNKNOWN/PRECHECK_ERROR" 2
    done
    local lk=${#kex_c[@]} lc=${#ciph_c[@]} lm=${#mac_c[@]} lh=${#hk_c[@]}
    (( lk > 0 && lc > 0 && lh > 0 )) || return 0
    local i k c m h z other_z
    local first_non_aead=""
    for c in "${ciph_c[@]}"; do
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) ;;
            *) first_non_aead="$c"; break ;;
        esac
    done

    while :; do
        k="${kex_c[0]:-}"
        c="${ciph_c[0]:-}"
        m="${mac_c[0]:-}"
        h="${hk_c[0]:-}"
        z=""
        for ((i=0; i<lk; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["kex|${kex_c[$i]}"]:-}" ]] || { k="${kex_c[$i]}"; break; }
        done
        for ((i=0; i<lc; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] || { c="${ciph_c[$i]}"; break; }
        done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do
                [[ -n "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] || { m="${mac_c[$i]}"; break; }
            done
        fi
        for ((i=0; i<lh; i++)); do
            [[ -n "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] || { h="${hk_c[$i]}"; break; }
        done
        for z in none zlib@openssh.com; do
            [[ -n "${PLAN_COVERAGE_SEEN["compression|$z"]:-}" ]] || break
            z=""
        done
        local uncovered=false
        for ((i=0; i<lk; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["kex|${kex_c[$i]}"]:-}" ]] && uncovered=true; done
        for ((i=0; i<lc; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["cipher|${ciph_c[$i]}"]:-}" ]] && uncovered=true; done
        for ((i=0; i<lh; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["hostkey|${hk_c[$i]}"]:-}" ]] && uncovered=true; done
        if [[ -n "$first_non_aead" ]]; then
            for ((i=0; i<lm; i++)); do [[ -z "${PLAN_COVERAGE_SEEN["mac|${mac_c[$i]}"]:-}" ]] && uncovered=true; done
        fi
        [[ -n "$z" ]] && uncovered=true
        [[ "$uncovered" == true ]] || break
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
                [[ -n "$first_non_aead" && -z "${PLAN_COVERAGE_SEEN["mac|$m"]:-}" ]] && c="$first_non_aead" ;;
        esac
        case "$c" in
            chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com) m="" ;;
        esac
        if [[ -n "$z" ]]; then
            add_test "国密/NORMAL coverage-driven: kex=$k cipher=$c mac=${m:-NONE} hostkey=$h compression=$z" \
                "$k" "$c" "$m" "$h" "国密/NORMAL/五维覆盖" 2 "$z"
            for other_z in none zlib@openssh.com; do
                [[ "$other_z" == "$z" || -n "${PLAN_COVERAGE_SEEN["compression|$other_z"]:-}" ]] && continue
                add_test "国密/NORMAL coverage-driven: kex=$k cipher=$c mac=${m:-NONE} hostkey=$h compression=$other_z" \
                    "$k" "$c" "$m" "$h" "国密/NORMAL/五维覆盖" 2 "$other_z"
            done
        else
            add_test "国密/NORMAL coverage-driven: kex=$k cipher=$c mac=${m:-NONE} hostkey=$h" \
                "$k" "$c" "$m" "$h" "国密/NORMAL/五维覆盖" 2
        fi
    done
    NORMAL_CANDIDATE_KEX=("${kex_c[@]}")
    NORMAL_CANDIDATE_CIPHER=("${ciph_c[@]}")
    NORMAL_CANDIDATE_MAC=("${mac_c[@]}")
    NORMAL_CANDIDATE_HOSTKEY=("${hk_c[@]}")
    NORMAL_CANDIDATE_COMPRESSION=(none zlib@openssh.com)
    repair_normal_coverage
}

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
load_worker_algorithms

if $LIST_ONLY; then
    # --list 绝不修改系统状态。
    case "$PROFILE" in
        modern)
            load_dynamic_tests ;;
        centos6)
            load_centos6_tests
            if sshd_effective_protocol_has_1 && ssh1_binary_supported; then
                load_ssh1_tests
            fi
            ;;
        openssh8)
            load_dynamic_tests
            load_openssh8_tests ;;
        openeuler)
            load_openeuler_tests
            load_dynamic_tests ;;
        *)
            ;;
    esac

    log "========================================"
    log "统一 SSH 算法协商测试项"
    log "环境：${OS_PRETTY}"
    log "OpenSSH：${SSH_VERSION_STR:-unknown}"
    log "Profile：${PROFILE}"
    log "========================================"
    log "列说明：default_supported=当前默认配置(sshd -T)是否已启用该算法"
    log "       （no 表示默认未启用但能力测试仍入选；n/a 用于 SSH-1）"
    log "========================================"
    i=0
    for d in "${DESCS[@]}"; do
        i=$((i + 1))
        printf '%3d. %-45s [protocol=SSH-%s kex=%s cipher=%s mac=%s hostkey=%s compression=%s default=%s]\n' \
            "$i" "$d" "${PROTOCOLS[$((i - 1))]}" \
            "${KEXES[$((i - 1))]:-N/A}" "${CIPHERS[$((i - 1))]:-N/A}" \
            "${MACS[$((i - 1))]:-N/A}" "${HOSTKEYS[$((i - 1))]:-N/A}" \
            "${COMPRESSIONS[$((i - 1))]:-N/A}" "${DEFAULT_FLAGS[$((i - 1))]:-n/a}" | tee -a "$LOG_FILE"
    done
    log "========================================"
    exit 0
fi

acquire_lock() {
    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        # 检查锁中的 PID 是否仍在运行；若已死则清理陈旧锁后重试
        local stale_pid=""
        [[ -f "$LOCK_DIR/pid" ]] && stale_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
        if [[ -n "$stale_pid" ]]; then
            if ! kill -0 "$stale_pid" 2>/dev/null; then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                if mkdir "$LOCK_DIR" 2>/dev/null; then
                    printf '%s\n' "$$" > "$LOCK_DIR/pid"
                    printf '%s\n' "$TS" > "$LOCK_DIR/start"
                    LOCK_ACQUIRED=true
                    return 0
                fi
            fi
        else
            # 锁目录存在但没有 pid 文件：这是上次运行在"mkdir 成功、尚未写入
            # pid"这一极窄窗口内被杀（例如 SIGKILL/断电）留下的残骸。正常
            # 退出路径下 release_lock 会先删 pid 再 rmdir，不会留下此形态。
            # 若永久保留它会导致后续每次启动都被判为"另一实例在运行"而无法
            # 自愈。为区分"真正的残骸"与"另一实例正在 mkdir 与写 pid 之间"，
            # 用目录 mtime 做宽限判断：仅当目录已存在超过 LOCK_STALE_GRACE 秒
            # 才回收，避免误抢活锁。
            local lock_mtime now age grace=10
            lock_mtime="$(stat -c %Y "$LOCK_DIR" 2>/dev/null || echo 0)"
            now="$(date +%s)"
            if [[ "$lock_mtime" -gt 0 ]]; then
                age=$(( now - lock_mtime ))
            else
                age=$grace
            fi
            if (( age >= grace )); then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                if mkdir "$LOCK_DIR" 2>/dev/null; then
                    printf '%s\n' "$$" > "$LOCK_DIR/pid"
                    printf '%s\n' "$TS" > "$LOCK_DIR/start"
                    LOCK_ACQUIRED=true
                    return 0
                fi
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

# 服务管理三函数（service_restart / wait_service_ready / service_is_up）必须
# 定义在下方"顶层执行序列"（acquire_lock/backup_config/install_recovery/...）
# 之前。原因：EXIT/INT/TERM trap 会在这些顶层语句的任意失败点触发
# restore_all/verify_restored_state，而它们内部会调用这几个函数。bash 是
# 运行时解析命令，若函数定义还未被读取到（定义位置在触发点之后），调用会
# 报 "command not found"，导致服务状态无法恢复、恢复验证误报 FAIL。
# 早期版本把这几个函数放在 3200 行之后，恰好落在 install_recovery 失败点
# 之后，故 die→trap 场景必然踩中，此处前移修正。
sshd_master_pid() {
    # 取当前 sshd 主进程（监听进程）PID。用于判断"重启"是否真的换了一个
    # 进程。OpenSSH 主进程的命令行形如 "sshd: /usr/sbin/sshd [listener]"。
    # 无匹配时输出空。
    #
    # 三级兜底（重要）：pgrep 来自 procps-ng，精简容器/云镜像（AlmaLinux、
    # openEuler 基础镜像等）默认可能未安装。若此处因缺少 pgrep 而拿不到 PID，
    # 会让上层 service_restart 误判"重启失败"，进而整轮测试中止。
    # 因此按 pgrep -f → pgrep -x → /proc 扫描 的顺序逐级降级，只要有一级
    # 可用即可。前两级未命中（或工具缺失）时不再报错，转入 /proc 扫描。
    local p=""
    if need_cmd pgrep; then
        p="$(pgrep -f 'sshd.*\[listener\]' 2>/dev/null | head -1)"
        [[ -n "$p" ]] || p="$(pgrep -x sshd 2>/dev/null | head -1)"
    fi
    [[ -n "$p" ]] && { printf '%s\n' "$p"; return 0; }

    # /proc 兜底：不依赖 procps-ng。优先匹配命令行含 "[listener]" 的进程
    # （即 sshd 主进程），其次匹配 comm 为 sshd 的进程。
    local d comm cmd
    for d in /proc/[0-9]*; do
        comm="$(cat "$d/comm" 2>/dev/null)" || continue
        [[ "$comm" == "sshd" ]] || continue
        cmd="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)"
        if [[ "$cmd" == *"[listener]"* ]]; then
            printf '%s\n' "${d#/proc/}"
            return 0
        fi
        [[ -n "$p" ]] || p="${d#/proc/}"
    done
    [[ -n "$p" ]] && printf '%s\n' "$p"
}

service_restart() {
    local before_pid="" after_pid=""

    # 记录重启前的主进程 PID，用于验证重启是否真正生效。
    case "$SERVICE" in
        ssh|sshd) before_pid="$(sshd_master_pid || true)" ;;
    esac

    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        systemctl restart "$SERVICE" >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        service "$SERVICE" restart >/dev/null 2>&1 || true
    else
        return 1
    fi

    # 关键校验：部分环境（容器/最小化系统）中 init 脚本依赖 PID 文件
    # （如 /run/sshd.pid）。若初始守护进程启动时未写该文件，`service restart`
    # 的 stop 阶段会因找不到 PID 而空转，start 阶段又发现端口已占用而直接
    # 返回成功——于是"重启"变成静默空操作，测试配置从未被加载，脚本会在
    # 默认配置上跑出完全错误的结论（例如固定 ssh-dss 却观察到默认 offer）。
    # 这里通过比较重启前后主进程 PID 来识别空操作并强制真正重启。
    if [[ "$SERVICE" == ssh || "$SERVICE" == sshd ]]; then
        local i
        for i in 1 2 3 4 5; do
            sleep 1
            after_pid="$(sshd_master_pid || true)"
            [[ -n "$after_pid" && "$after_pid" != "$before_pid" ]] && return 0
        done
        # PID 未变化 = init 重启未生效：先尝试 HUP 让主进程重读配置
        # （HUP 同时会补写 PID 文件，使后续 service 操作恢复正常），
        # 仍不生效则直接杀掉主进程并重新启动。
        if [[ -n "$after_pid" ]]; then
            kill -HUP "$after_pid" >/dev/null 2>&1 || true
            sleep 2
            after_pid="$(sshd_master_pid || true)"
            # HUP 重读配置但不换进程，PID 不变属正常；此处再确认服务在监听
            sshd_port_listening && return 0
            kill "$after_pid" >/dev/null 2>&1 || true
            sleep 2
        fi
        if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
            systemctl start "$SERVICE" >/dev/null 2>&1 || true
        elif command -v service >/dev/null 2>&1; then
            service "$SERVICE" start >/dev/null 2>&1 || true
        fi
        sleep 1
        after_pid="$(sshd_master_pid || true)"
        [[ -n "$after_pid" ]]
        return $?
    fi

    return 0
}

sshd_port_listening() {
    # 直接探测 sshd 是否真的在 PORT 上监听/可连接。
    #
    # 为什么需要这一层：容器、最小化发行版或被非 init 方式启动的 sshd，
    # 其 `service ssh status` 依赖 PID 文件（如 /run/sshd.pid）。当 PID 文件
    # 缺失时 status 会误报 "not running"（退出码 3），而 sshd 进程其实已在
    # 监听端口。若 service_is_up 只信 status，就会把"服务正常"误判为
    # "服务未启动"，进而让每个 TEST_CASE 都在重启轮询里超时、全部记
    # SERVER_DOWN。这里用真实的端口可连接性作为权威证据。
    #
    # 优先用 bash 内建 /dev/tcp（无外部依赖）；不可用时退回 ss/netstat。
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3<&- 2>/dev/null || true
        exec 3>&- 2>/dev/null || true
        return 0
    fi
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$" && return 0
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}\$" && return 0
    fi
    return 1
}

service_is_up() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        if systemctl is-active --quiet "$SERVICE"; then
            return 0
        fi
        # systemd 判定为未激活时，再用端口探测兜底：某些容器里 systemd
        # 状态与真实进程不一致（或 socket activation 导致 unit 未 active）。
        sshd_port_listening && return 0
        return 1
    fi

    if command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        if service "$SERVICE" status >/dev/null 2>&1; then
            return 0
        fi
        # status 依赖 PID 文件，容器/最小化环境中常不可靠；改以端口可连接性
        # 为准，避免把已正常运行的服务误判为未启动。
        sshd_port_listening && return 0
        return 1
    fi

    # 无可用 init 工具：只能以端口探测为准。
    sshd_port_listening
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
env_log "Worker 算法基线: $WORKER_ALGORITHM_FILE"
for command_name in ssh sshd ssh-keygen awk grep sed tr cut head tail stat mktemp date cmp; do
    env_log "命令 ${command_name}: $(need_cmd "$command_name" && echo available || echo missing)"
done
# procps 系工具（pgrep/ps）单独提示：它们来自 procps-ng，精简镜像常缺失。
# 脚本已为 sshd_master_pid 提供 /proc 兜底（缺 pgrep 也能跑），因此这里只做
# 可操作性提示、不中止；ps 仅用于 systemd 探测，缺失时同样有 /run/systemd
# 目录兜底。
for command_name in pgrep ps; do
    if need_cmd "$command_name"; then
        env_log "命令 ${command_name}: available"
    else
        env_log "命令 ${command_name}: missing（已启用 /proc 兜底，可继续；如需完整功能可安装 procps-ng）"
        env_log "  安装提示: yum install -y procps-ng   # 或 dnf install -y procps-ng / apt-get install -y procps"
    fi
done
env_log "命令 systemctl: $(need_cmd systemctl && echo available || echo missing)"
env_log "命令 service: $(need_cmd service && echo available || echo missing)"
env_log "命令 journalctl: $(need_cmd journalctl && echo available || echo missing)"
env_log "命令 crontab: $(need_cmd crontab && echo available || echo missing)"
env_log "服务管理选择: INIT=$INIT SERVICE=$SERVICE"
env_log "崩溃自愈可用性: $( $RECOVERY_SELFHEAL_UNAVAILABLE && echo '不可用（无自愈模式）' || echo '已尝试安装' )"

if load_default_effective_algorithms; then
    env_log "默认 sshd -T kexalgorithms: ${DEFAULT_KEX//$'\n'/,}"
    env_log "默认 sshd -T ciphers: ${DEFAULT_CIPHER//$'\n'/,}"
    env_log "默认 sshd -T macs: ${DEFAULT_MAC//$'\n'/,}"
    env_log "默认 sshd -T hostkey: ${DEFAULT_HOSTKEY//$'\n'/,}"
    env_log "默认 sshd -T hostkeyalgorithms: ${DEFAULT_HOSTKEY_ALGORITHMS//$'\n'/,}"
    env_log "默认 sshd -T compression: ${DEFAULT_COMPRESSION:-unknown}"
else
    env_log "WARNING：无法读取默认 sshd -T 有效配置"
fi

# ============================================================
# 初始服务状态 / crypto-policies 状态记录
# ============================================================
record_initial_state() {
    # 记录初始服务状态时，必须与 verify_restored_state 使用同一套判定口径
    # （即 service_is_up）。否则容器/最小化环境中 `service ssh status` 因
    # PID 文件缺失误报 "not running"，会把初始状态记成"已停止"；测试结束后
    # service_is_up 的端口兜底又判定"运行中"，导致恢复验证出现
    # "应停止但仍运行" 的假 FAIL。统一走 service_is_up 可消除该不对称。
    if [[ "$SERVICE" != "unknown" ]] &&
        { [[ "$INIT" == "systemd" ]] || command -v service >/dev/null 2>&1; }; then
        if service_is_up; then
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
    # SC2174：mkdir -p -m 只作用于最深层目录。STATE_ROOT(/var/lib/ssh-algo-unified)
    # 若不存在会以默认 umask 创建，这里显式创建并收紧权限为 700。
    if [[ ! -d "${STATE_ROOT}" ]]; then
        mkdir -p "${STATE_ROOT}" 2>/dev/null || true
        chmod 700 "${STATE_ROOT}" 2>/dev/null || true
    fi
    mkdir -p "$STATE_DIR" || die "无法创建状态目录：$STATE_DIR"
    chmod 700 "$STATE_DIR" 2>/dev/null || true
    STATE_DIR_CREATED=true
    TMP_DIR="$STATE_DIR"
    # 状态目录就绪后立即把日志迁入受保护目录（此前日志临时落在 BASE_DIR）。
    initialize_log_file
    AUTO_KEY="${STATE_DIR}/algo_test_key"
    AUTO_PUB="${AUTO_KEY}.pub"
    AUTO_SSH1_KEY="${STATE_DIR}/algo_test_ssh1_key"
    AUTO_SSH1_PUB="${AUTO_SSH1_KEY}.pub"
    cp -a "$SSHD_CONFIG" "$BACKUP_FILE" || die "无法备份 $SSHD_CONFIG"
    chmod 600 "$BACKUP_FILE" || true
    # 备份已成功落盘：自此之后对宿主的任何改动都可依据备份回滚，
    # 置位该标志使 restore_all 走完整恢复流程（见其早退保护）。
    STATE_MUTATION_STARTED=true
    env_log "配置备份: $BACKUP_FILE"
    env_log "状态目录: $STATE_DIR"
}

verify_restored_state() {
    local cfg_ok=true svc_ok=true crypto_ok=true temp_ok=true auth_ok=true sshdir_ok=true hostkeys_ok=true

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

    if [[ -f "${BACKUP_FILE}.authkeys.added" ]]; then
        if [[ ! -e "$AUTHORIZED_KEYS_FILE" ]] ||
           ! grep -Fxf "${BACKUP_FILE}.authkeys.added" "$AUTHORIZED_KEYS_FILE" >/dev/null 2>&1; then
            log "[恢复验证] authorized_keys: PASS（测试行已移除，外部修改保留）"
        else
            auth_ok=false
            log "[恢复验证] authorized_keys: FAIL（测试行仍存在）"
        fi
    elif [[ -f "${BACKUP_FILE}.authkeys.absent" && ! -e "$AUTHORIZED_KEYS_FILE" ]]; then
        log "[恢复验证] authorized_keys: PASS（测试前不存在）"
    fi

    if [[ "$SSH_DIR_WAS_ABSENT" == true ]]; then
        if [[ -e /root/.ssh ]]; then
            sshdir_ok=false
            log "[恢复验证] /root/.ssh: FAIL（测试前不存在但当前仍存在）"
        else
            log "[恢复验证] /root/.ssh: PASS（测试前不存在）"
        fi
    elif [[ -d /root/.ssh && -n "$SSH_DIR_MODE_BEFORE" ]]; then
        local final_mode
        final_mode="$(stat -c %a /root/.ssh 2>/dev/null || stat -f %Lp /root/.ssh 2>/dev/null || true)"
        if [[ "$final_mode" == "$SSH_DIR_MODE_BEFORE" ]]; then
            log "[恢复验证] /root/.ssh mode: PASS ($final_mode)"
        else
            sshdir_ok=false
            log "[恢复验证] /root/.ssh mode: FAIL（当前='$final_mode'，期望='$SSH_DIR_MODE_BEFORE'）"
        fi
    fi

    local _hk _private_id _public_id _current_private_id _current_public_id
    if [[ -f "$GENERATED_HOST_KEYS_FILE" ]]; then
        while IFS=$'\t' read -r _hk _private_id _public_id; do
            [[ -n "$_hk" ]] || continue
            _current_private_id="$(hostkey_file_identity "$_hk" 2>/dev/null || true)"
            _current_public_id="$(hostkey_file_identity "${_hk}.pub" 2>/dev/null || true)"
            if [[ -e "$_hk" || -e "${_hk}.pub" ]]; then
                if [[ "$_current_private_id" == "$_private_id" &&
                      "$_current_public_id" == "$_public_id" ]]; then
                    hostkeys_ok=false
                    log "[恢复验证] HostKey cleanup: FAIL（仍存在 $_hk）"
                else
                    log "[恢复验证] HostKey cleanup: PASS（身份变化，保留外部替换 $_hk）"
                fi
            fi
        done < "$GENERATED_HOST_KEYS_FILE"
    fi
    $hostkeys_ok && log "[恢复验证] HostKey cleanup: PASS"

    if find "$TMP_DIR" -maxdepth 1 -type f \( -name 'algo_client.*' -o -name 'algo_sshd_t.*' -o -name 'ssh_algo_probe.*' -o -name 'ssh_algo_single.*' -o -name 'ssh1probe.*' \) -print -quit 2>/dev/null | grep -q .; then
        temp_ok=false
        log "[恢复验证] temporary files: FAIL（发现测试临时文件）"
    else
        log "[恢复验证] temporary files: PASS（CLEAN）"
    fi

    if $cfg_ok && $svc_ok && $crypto_ok && $temp_ok && $auth_ok && $sshdir_ok && $hostkeys_ok; then
        log "[恢复验证] 总体：PASS"
        return 0
    fi
    log "[恢复验证] 总体：FAIL，请检查上述恢复验证日志"
    return 1
}

restore_all() {
    $RESTORED && return
    RESTORED=true

    # 早退保护：若备份尚未建立（STATE_MUTATION_STARTED=false），说明脚本在
    # 改动宿主之前就退出了（抢锁失败 / sshd_config 缺失 / 参数校验不过等）。
    # 此时系统原封未动，既无配置可恢复，也无服务需重启；若照常走完整恢复流程，
    # 会因"缺少 BACKUP_FILE"误报恢复失败并强制非零退出码，掩盖真实原因。
    # 这里只清理可能已抢到的锁，然后按成功返回（保留调用点原退出码）。
    if ! $STATE_MUTATION_STARTED; then
        release_lock
        RESTORE_EXIT_CODE=0
        return 0
    fi

    printf '\n' | tee -a "$LOG_FILE"
    log "[恢复] 开始恢复配置、服务状态和临时文件..."

    # 若脚本在 ssh 客户端运行期间被 INT/TERM/EXIT trap 打断，此处终止并回收
    # 仍在后台运行的客户端进程。这里必须尊重子进程的退出状态（`|| true`），
    # 否则在 set -e 之外的场景下 wait 的非零返回会污染后续恢复流程。
    if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    CLIENT_PID=""

    # 自动模式认证文件恢复：恢复测试前精确快照；若原来不存在则删除。
    if $AUTO_AUTH_KEY_ADDED || [[ -f "${BACKUP_FILE}.authkeys.active" ]]; then
        local auth_restore_tmp=""
        if [[ -f "${BACKUP_FILE}.authkeys.added" && -e "$AUTHORIZED_KEYS_FILE" ]]; then
            auth_restore_tmp="$(mktemp "${TMP_DIR}/authorized_keys.restore.XXXXXX" 2>/dev/null || true)"
            if [[ -n "$auth_restore_tmp" ]] &&
               { grep -Fvxf "${BACKUP_FILE}.authkeys.added" "$AUTHORIZED_KEYS_FILE" > "$auth_restore_tmp" || [[ $? -eq 1 ]]; } &&
               chmod 600 "$auth_restore_tmp" && mv -f "$auth_restore_tmp" "$AUTHORIZED_KEYS_FILE"; then
                log "[恢复] authorized_keys 已移除本测试行，外部修改保留"
                if [[ "$AUTHORIZED_KEYS_WAS_ABSENT" == true && ! -s "$AUTHORIZED_KEYS_FILE" ]]; then
                    rm -f "$AUTHORIZED_KEYS_FILE" || RESTORE_FAILED=true
                fi
            else
                log "[恢复] ERROR：authorized_keys 测试行清理失败"
                RESTORE_FAILED=true
                [[ -n "$auth_restore_tmp" ]] && rm -f "$auth_restore_tmp"
            fi
        elif [[ -f "${BACKUP_FILE}.authkeys.added" ]]; then
            log "[恢复] authorized_keys 当前不存在，测试行已自然清理"
        elif [[ -f "${BACKUP_FILE}.authkeys" ]]; then
            log "[恢复] WARNING：缺少测试行清单，保留 authorized_keys，未整体覆盖外部修改"
        elif [[ -f "${BACKUP_FILE}.authkeys.absent" && ! -e "$AUTHORIZED_KEYS_FILE" ]]; then
            log "[恢复] authorized_keys 已恢复为测试前不存在状态"
        elif [[ -f "${BACKUP_FILE}.authkeys.absent" ]]; then
            log "[恢复] WARNING：authorized_keys 含外部内容，保留文件而不整体删除"
        else
            log "[恢复] WARNING：无 authorized_keys 恢复元数据，保留当前文件"
        fi
        if [[ -f "${BACKUP_FILE}.authkeys.added" ]] &&
           [[ -e "$AUTHORIZED_KEYS_FILE" ]] &&
           grep -Fxf "${BACKUP_FILE}.authkeys.added" "$AUTHORIZED_KEYS_FILE" >/dev/null 2>&1; then
            RESTORE_FAILED=true
        fi
    fi

    # 恢复 /root/.ssh 的测试前状态。若测试前目录不存在，则只在目录为空时删除。
    if [[ -f "${BACKUP_FILE}.sshdir.absent" ]]; then
        if rmdir /root/.ssh 2>/dev/null; then
            log "[恢复] /root/.ssh 已恢复为测试前不存在状态"
        elif [[ ! -d /root/.ssh ]]; then
            :
        else
            log "[恢复] ERROR：测试前 /root/.ssh 不存在，但测试后目录无法安全删除（可能含外部文件）"
            RESTORE_FAILED=true
        fi
    elif [[ -f "${BACKUP_FILE}.sshdir.state" && -d /root/.ssh ]]; then
        local sshdir_mode sshdir_uid sshdir_gid
        sshdir_mode="$(sed -n '1p' "${BACKUP_FILE}.sshdir.state" 2>/dev/null || true)"
        sshdir_uid="$(sed -n '2p' "${BACKUP_FILE}.sshdir.state" 2>/dev/null || true)"
        sshdir_gid="$(sed -n '3p' "${BACKUP_FILE}.sshdir.state" 2>/dev/null || true)"
        if [[ -n "$sshdir_mode" ]] && ! chmod "$sshdir_mode" /root/.ssh 2>/dev/null; then
            log "[恢复] ERROR：无法恢复 /root/.ssh 权限：$sshdir_mode"
            RESTORE_FAILED=true
        fi
        if [[ -n "$sshdir_uid" && -n "$sshdir_gid" ]]; then
            chown "$sshdir_uid:$sshdir_gid" /root/.ssh 2>/dev/null || { log "[恢复] ERROR：无法恢复 /root/.ssh 所有者"; RESTORE_FAILED=true; }
        fi
    fi
    rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"

    # 恢复测试前的 sshd_config；整个恢复过程使用同目录临时文件 + mv，避免半写状态。
    # 三种情形：
    #   A. 当前配置仍带测试 marker —— 本次测试写入尚未回滚，需用备份覆盖回去；
    #   B. 当前配置已不含 marker 且与备份一致 —— 说明 restore_after_test 已在本轮
    #      收尾时恢复到位（这是“正常跑完”的主路径），视为恢复成功，绝不能判失败；
    #   C. 当前配置不含 marker 且与备份不一致 —— 才是“测试期间被外部修改”，
    #      此时不覆盖其修改，保留备份并记警告。
    # 旧实现把 A 之外的两种一律并入 C 判失败，导致每次正常结束都被误报
    # “外部修改 + 恢复失败”，进而强改退出码并跳过自愈钩子清理。
    if [[ -f "$BACKUP_FILE" ]]; then
        if grep -qF 'ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT' "$SSHD_CONFIG" 2>/dev/null; then
            local restore_tmp
            restore_tmp="$(mktemp "${SSHD_CONFIG}.restore.XXXXXX")"
            if cp -a "$BACKUP_FILE" "$restore_tmp" && mv -f "$restore_tmp" "$SSHD_CONFIG"; then
                if [[ -n "$SSHD_BIN" ]] &&
                   "$SSHD_BIN" -t -f "$SSHD_CONFIG" >/dev/null 2>&1; then
                    CONFIG_RESTORED_CONFIRMED=true
                    log "[恢复] sshd_config 已恢复并通过校验"
                else
                    log "[恢复] ERROR：sshd_config 已写回但校验失败，保留恢复依据"
                    RESTORE_FAILED=true
                fi
            else
                log "[恢复] ERROR：sshd_config 恢复失败"
                RESTORE_FAILED=true
                rm -f "$restore_tmp"
            fi
        elif cmp -s "$BACKUP_FILE" "$SSHD_CONFIG"; then
            # 情形 B：已恢复到位（正常结束路径）
            CONFIG_RESTORED_CONFIRMED=true
            log "[恢复] sshd_config 与备份一致，确认已恢复（无需再次覆盖）"
        else
            # 情形 C：被外部修改
            log "[恢复] WARNING：sshd_config 已被外部修改（不含测试 marker），跳过恢复以避免覆盖外部修改；保留恢复依据"
            RESTORE_FAILED=true
        fi
    else
        log "[恢复] ERROR：缺少 sshd_config 备份，保留现有恢复依据"
        RESTORE_FAILED=true
    fi

    # 只有私钥和公钥身份都仍与本次生成记录一致时才删除，避免误删
    # 测试期间被管理员/配置管理工具替换的外部 HostKey。
    local hk private_id public_id current_private_id current_public_id
    if [[ -f "$GENERATED_HOST_KEYS_FILE" ]]; then
        while IFS=$'\t' read -r hk private_id public_id; do
            [[ -n "$hk" ]] || continue
            current_private_id="$(hostkey_file_identity "$hk" 2>/dev/null || true)"
            current_public_id="$(hostkey_file_identity "${hk}.pub" 2>/dev/null || true)"
            if [[ -n "$private_id" && -n "$public_id" &&
                  "$current_private_id" == "$private_id" &&
                  "$current_public_id" == "$public_id" ]]; then
                if rm -f "$hk" "${hk}.pub"; then
                    log "[恢复] 删除本次生成的 HostKey：$hk"
                else
                    log "[恢复] ERROR：删除本次生成的 HostKey 失败：$hk"
                    RESTORE_FAILED=true
                fi
            elif [[ -e "$hk" || -e "${hk}.pub" ]]; then
                log "[恢复] WARNING：HostKey 身份已变化，跳过删除以保护外部替换：$hk"
            fi
        done < "$GENERATED_HOST_KEYS_FILE"
    fi

    if $CRYPTO_POLICY_CHANGED && command -v update-crypto-policies >/dev/null 2>&1 && [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
        local current_crypto=""
        current_crypto="$(update-crypto-policies --show 2>/dev/null || true)"
        # 只有"当前值 == 本脚本写入的值"才恢复；与常量 LEGACY 比较会把
        # 他人恰好在测试期间设成的 LEGACY 误判为本脚本所为而覆盖。
        if [[ -n "$CRYPTO_POLICY_APPLIED" && "$current_crypto" == "$CRYPTO_POLICY_APPLIED" ]]; then
            if update-crypto-policies --set "$INITIAL_CRYPTO_POLICY" >/dev/null 2>&1; then
                log "[恢复] crypto-policy 已恢复：$INITIAL_CRYPTO_POLICY"
            else
                log "[恢复] ERROR：crypto-policy 恢复失败"
                RESTORE_FAILED=true
            fi
        else
            log "[恢复] WARNING：crypto-policy 当前为 '$current_crypto'，不是本脚本设置的 '$CRYPTO_POLICY_APPLIED'；跳过恢复，避免覆盖其他进程的修改"
        fi
    fi

    rm -f "$TMP_DIR"/algo_client.* "$TMP_DIR"/algo_sshd_t.* \
        "$TMP_DIR"/ssh_algo_probe.* "$TMP_DIR"/ssh_algo_single.* "$TMP_DIR"/ssh1probe.* 2>/dev/null || true
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
                RESTORE_FAILED=true
            fi
        else
            local stop_ok=true
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || stop_ok=false
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || stop_ok=false
            fi
            if $stop_ok; then
                log "[恢复] 服务状态：恢复为测试前停止状态"
            else
                log "[恢复] ERROR：无法恢复 sshd 为测试前停止状态"
                RESTORE_FAILED=true
            fi
        fi
    fi

    # 只有确认 sshd_config 已恢复，才还原/删除自愈钩子；否则必须保留
    # helper、drop-in 和备份，供下一次自愈继续使用。
    if $CONFIG_RESTORED_CONFIRMED; then
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
            if [[ -n "$SYSTEMD_DROPIN_FILE" &&
                  -z "${PREEXISTING_PATH_SEEN[$SYSTEMD_DROPIN_FILE]:-}" &&
                  "$SYSTEMD_DROPIN_PREEXISTING" != true ]]; then
                rm -f "$SYSTEMD_DROPIN_FILE"
            fi
            if [[ -n "$SYSTEMD_DROPIN_DIR" ]]; then rmdir "$SYSTEMD_DROPIN_DIR" 2>/dev/null || true; fi
            if [[ -z "${PREEXISTING_PATH_SEEN[$RESTORE_HELPER]:-}" &&
                  "$RESTORE_HELPER_PREEXISTING" != true ]]; then
                rm -f "$RESTORE_HELPER"
            fi
            systemctl daemon-reload >/dev/null 2>&1 || true
        elif [[ "$INIT" == "sysv/service" ]] && command -v crontab >/dev/null 2>&1; then
            local cron_now cron_tmp
            cron_now="$(crontab -l 2>/dev/null || true)"
            cron_tmp="$(mktemp "${TMP_DIR}/ssh-algo-unified-cron-clean.XXXXXX" 2>/dev/null || true)"
            if [[ -n "$cron_tmp" ]]; then
                printf '%s\n' "$cron_now" | grep -vF "$CRON_TAG" > "$cron_tmp" || true
                crontab "$cron_tmp" 2>/dev/null || true
                rm -f "$cron_tmp"
            fi
            if [[ -z "${PREEXISTING_PATH_SEEN[$RESTORE_HELPER]:-}" &&
                  "$RESTORE_HELPER_PREEXISTING" != true ]]; then
                rm -f "$RESTORE_HELPER"
            fi
        fi
    else
        log "[恢复] WARNING：未确认 sshd_config 已恢复，保留 backup/state/helper/drop-in"
    fi

    if ! verify_restored_state; then
        RESTORE_FAILED=true
    fi

    if $STATE_DIR_CREATED && ! $RESTORE_FAILED; then
        rm -rf -- "$STATE_DIR"
        STATE_DIR_CREATED=false
    elif $STATE_DIR_CREATED; then
        log "[恢复] 失败状态保留：$STATE_DIR"
    fi
    release_lock
    log "[恢复] 临时文件和测试客户端已清理"
    if $RESTORE_FAILED; then
        log "[恢复] ERROR：存在恢复失败项；为避免 sshd 停留在测试配置上，脚本以非零码退出。"
        # 不在本函数内 exit：本函数会作为 EXIT/INT/TERM trap 的回调被调用，
        # 内部 exit 会改写真实退出码（丢失 INT=130 / TERM=143），也与
        # trap ... EXIT 叠加存在递归风险。改为置位 RESTORE_FAILED 并返回
        # 非零，退出码由各调用点自行决定。
        RESTORE_EXIT_CODE=1
        return 1
    fi
    RESTORE_EXIT_CODE=0
    log "[恢复] 完成"
    return 0
}

backup_preexisting() {
    # 若目标路径已存在且不是本测试之前创建的（不含 ALGO_TEST marker），
    # 备份到 STATE_DIR，恢复时通过 PREEXISTING_BACKUPS 还原，避免覆盖管理员原有文件。
    local f="$1"
    [[ -n "$f" && -e "$f" ]] || return 0
    local bak=""
    bak="$STATE_DIR/preexisting_$(basename "$f").$$"
    if cp -a "$f" "$bak" 2>/dev/null; then
        PREEXISTING_BACKUPS+=("$f|$bak")
        PREEXISTING_PATH_SEEN["$f"]=1
        env_log "备份被覆盖路径（恢复时还原）: $f -> $bak"
        return 0
    fi
    log "[恢复] ERROR：无法备份将被覆盖的已有路径：$f"
    return 1
}

inject_helper_values() {
    # 把自愈脚本里的 @NAME@ 占位符替换为真实值。
    # 设计要点：
    # 1) 值以单引号包裹写出：helper 是 bash 脚本，路径若含 $ / ` / \ 会在
    #    执行时被二次展开（如工作目录 /opt/work$dir），单引号可保持字面量，
    #    内部单引号按 '\'' 规则转义。
    # 2) 占位符用 @NAME@ 而非 ${NAME}：helper 正文里有 AUTH_BACKUP="${BACKUP}.authkeys"
    #    这类引用“已注入变量”的行，占位符若写成 ${BACKUP} 会被误替换。
    # 3) 用 awk 单次从左到右扫描替换：匹配即插入值并跳过，绝不回头扫描已插入
    #    文本，因此即使某个真实值里含 "@BACKUP@" 之类字面量也不会被二次替换；
    #    基于 substr 的字面拼接也不受 & \ 等替换串元字符影响。
    local file="$1"
    [[ -f "$file" ]] || return 1

    # 分支专属变量的统一入口：helper_backup/dropin_backup 等只在 systemd 或
    # SysV 其中一支被声明为调用方的 local，另一支没有。本函数是独立函数，
    # 在 set -u 下直接引用另一支未声明的变量会 unbound 崩溃（CentOS 6 走 SysV
    # 分支即中招）。这里一次性收敛，缺省即空/假，彻底解除对调用方作用域的依赖。
    local helper_backup="${helper_backup:-}"
    local helper_preexisting="${helper_preexisting:-false}"
    local dropin_backup="${dropin_backup:-}"
    local dropin_preexisting="${dropin_preexisting:-false}"
    local SYSTEMD_DROPIN_FILE="${SYSTEMD_DROPIN_FILE:-}"
    local SYSTEMD_DROPIN_DIR="${SYSTEMD_DROPIN_DIR:-}"

    # 生成 NAME<TAB>value 映射，值统一单引号化
    local map
    map="$(mktemp "${TMP_DIR}/helper_map.XXXXXX" 2>/dev/null || mktemp /tmp/helper_map.XXXXXX)" || return 1
    _emit_pair() {
        local name="$1" val="$2"
        printf '%s\t%s\n' "$name" "'${val//\'/\'\\\'\'}'"
    }
    {
        _emit_pair CONFIG              "$SSHD_CONFIG"
        _emit_pair BACKUP              "$BACKUP_FILE"
        _emit_pair SERVICE             "$SERVICE"
        _emit_pair INITIAL_SERVICE_KNOWN "$INITIAL_SERVICE_KNOWN"
        _emit_pair INITIAL_SERVICE_ACTIVE "$INITIAL_SERVICE_ACTIVE"
        _emit_pair PIDFILE             "$PID_FILE"
        _emit_pair AUTH_FILE           "$AUTHORIZED_KEYS_FILE"
        _emit_pair HELPER              "$RESTORE_HELPER"
        _emit_pair HOSTKEY_LIST        "$GENERATED_HOST_KEYS_FILE"
        _emit_pair CRYPTO_STATE        "$CRYPTO_POLICY_STATE_FILE"
        _emit_pair AUTO_KEY            "$AUTO_KEY"
        _emit_pair AUTO_PUB            "$AUTO_PUB"
        _emit_pair AUTO_SSH1_KEY       "$AUTO_SSH1_KEY"
        _emit_pair AUTO_SSH1_PUB       "$AUTO_SSH1_PUB"
        _emit_pair DROPIN              "$SYSTEMD_DROPIN_FILE"
        _emit_pair DROPIN_DIR          "$SYSTEMD_DROPIN_DIR"
        _emit_pair HELPER_BACKUP       "$helper_backup"
        _emit_pair HELPER_PREEXISTING  "$helper_preexisting"
        _emit_pair DROPIN_BACKUP       "$dropin_backup"
        _emit_pair DROPIN_PREEXISTING  "$dropin_preexisting"
    } > "$map" || { rm -f "$map"; return 1; }

    local out="$file.repl"
    awk -F'\t' '
        NR==FNR { v[$1]=substr($0, index($0,$2)); next }
        {
            o=""; r=$0
            while (match(r, /@[A-Z0-9_]+@/)) {
                tok=substr(r, RSTART+1, RLENGTH-2)
                o = o substr(r,1,RSTART-1) (tok in v ? v[tok] : substr(r,RSTART,RLENGTH))
                r = substr(r, RSTART+RLENGTH)
            }
            print o r
        }
    ' "$map" "$file" > "$out" || { rm -f "$map" "$out"; return 1; }
    rm -f "$map"
    mv -f "$out" "$file" || { rm -f "$out"; return 1; }
    return 0
}

install_recovery() {
    # PID 文件写入 2 字段：PID 和进程启动时间（/proc/[pid]/stat 第 22 字段），
    # 供崩溃自愈 helper 比对，避免 PID 被其它进程复用后误判“原测试仍在运行”。
    echo "$$ $(awk '{print $22}' /proc/$$/stat 2>/dev/null || echo 0)" > "$PID_FILE" || die "无法创建 PID 文件：$PID_FILE"

    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        SYSTEMD_DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
        SYSTEMD_DROPIN_FILE="${SYSTEMD_DROPIN_DIR}/ssh-algo-unified.conf"

        local helper_tmp dropin_tmp helper_preexisting=false dropin_preexisting=false
        local helper_backup="" dropin_backup=""
        helper_backup="${STATE_DIR}/preexisting_$(basename "$RESTORE_HELPER").$$"
        dropin_backup="${STATE_DIR}/preexisting_$(basename "$SYSTEMD_DROPIN_FILE").$$"
        if [[ -e "$RESTORE_HELPER" ]]; then
            helper_preexisting=true
            RESTORE_HELPER_PREEXISTING=true
        fi
        if [[ -e "$SYSTEMD_DROPIN_FILE" ]]; then
            dropin_preexisting=true
            SYSTEMD_DROPIN_PREEXISTING=true
        fi
        if ! mkdir -p "$(dirname "$RESTORE_HELPER")"; then
            log "[恢复] ERROR：无法创建恢复脚本目录：$(dirname "$RESTORE_HELPER")"
            return 1
        fi
        helper_tmp="$(mktemp "${RESTORE_HELPER}.XXXXXX")" || {
            log "[恢复] ERROR：无法创建恢复脚本临时文件"
            return 1
        }
        # 注意：分隔符必须用 <<'EOF'（带引号）关闭 here-doc 内插值。带引号的
        # here-doc 不做任何展开，因此 helper 正文里的变量引用必须写成**裸写法
        # （$VAR / ${VAR}）**，执行 helper 时才会展开为真实值。
        # 切勿写成 \$VAR：在带引号 here-doc 中反斜杠会被原样写入文件，bash 执行
        # 时双引号内的 "\$VAR" 又会被解析为字面量 $VAR（转义美元符）而不展开，
        # 导致所有路径判定恒为假、崩溃自愈彻底失效。
        # 真正的值是靠 inject_helper_values 注入的：正文里待替换的路径写成
        # @NAME@ 单 token 占位符，注入时以单引号包裹，从而保证路径里含
        # $ / ` / \ 时不会被二次展开。
        if ! cat > "$helper_tmp" <<'EOF'
#!/bin/bash
set -u
CONFIG=@CONFIG@
BACKUP=@BACKUP@
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
PIDFILE=@PIDFILE@
SERVICE=@SERVICE@
INITIAL_SERVICE_KNOWN=@INITIAL_SERVICE_KNOWN@
INITIAL_SERVICE_ACTIVE=@INITIAL_SERVICE_ACTIVE@
DROPIN=@DROPIN@
DROPIN_DIR=@DROPIN_DIR@
HELPER=@HELPER@
HELPER_BACKUP=@HELPER_BACKUP@
HELPER_PREEXISTING=@HELPER_PREEXISTING@
DROPIN_BACKUP=@DROPIN_BACKUP@
DROPIN_PREEXISTING=@DROPIN_PREEXISTING@
AUTH_FILE=@AUTH_FILE@
AUTH_BACKUP="${BACKUP}.authkeys"
AUTH_ADDED="${BACKUP}.authkeys.added"
AUTH_ABSENT="${BACKUP}.authkeys.absent"
AUTH_ACTIVE="${BACKUP}.authkeys.active"
SSHDIR_ABSENT="${BACKUP}.sshdir.absent"
SSHDIR_STATE="${BACKUP}.sshdir.state"
HOSTKEY_LIST=@HOSTKEY_LIST@
CRYPTO_STATE=@CRYPTO_STATE@
AUTO_KEY=@AUTO_KEY@
AUTO_PUB=@AUTO_PUB@
AUTO_SSH1_KEY=@AUTO_SSH1_KEY@
AUTO_SSH1_PUB=@AUTO_SSH1_PUB@

hostkey_file_identity() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        ssh-keygen -lf "$file" 2>/dev/null | awk 'NR == 1 {print $2}'
    fi
}

restore_needed=false
if [[ -f "$PIDFILE" ]]; then
    pidline="$(cat "$PIDFILE" 2>/dev/null || true)"
    pid_num="$(printf '%s' "$pidline" | awk '{print $1}')"
    pid_start="$(printf '%s' "$pidline" | awk '{print $2}')"
    if [[ -z "$pid_num" ]] || ! kill -0 "$pid_num" 2>/dev/null; then
        restore_needed=true
    else
        cur_start="$(awk '{print $22}' "/proc/$pid_num/stat" 2>/dev/null || echo 0)"
        [[ -z "$pid_start" || "$pid_start" != "$cur_start" ]] && restore_needed=true
    fi
elif [[ -f "$BACKUP" || -f "$AUTH_BACKUP" || -f "$AUTH_ADDED" || -f "$AUTH_ABSENT" || -f "$AUTH_ACTIVE" || -f "$HOSTKEY_LIST" || -f "$CRYPTO_STATE" ]]; then
    restore_needed=true
fi

if $restore_needed; then
    recovery_ok=true
    config_restored=false
    if [[ -f "$BACKUP" ]] && grep -qF "$MARKER" "$CONFIG" 2>/dev/null; then
        t="$(mktemp "${CONFIG}.recover.XXXXXX")"
        if cp -a "$BACKUP" "$t" && mv -f "$t" "$CONFIG"; then
            config_restored=true
        else
            rm -f "$t"
            recovery_ok=false
        fi
    else
        # 没有成功覆盖测试配置就不能确认恢复目标，必须保留全部恢复依据。
        recovery_ok=false
    fi

    if [[ -f "$AUTH_ADDED" && -e "$AUTH_FILE" ]]; then
        at="$(mktemp "${BACKUP}.authkeys.recover.XXXXXX" 2>/dev/null || true)"
        if [[ -n "$at" ]] &&
           { grep -Fvxf "$AUTH_ADDED" "$AUTH_FILE" > "$at" || [[ $? -eq 1 ]]; } &&
           chmod 600 "$at" && mv -f "$at" "$AUTH_FILE"; then
            :
        else
            rm -f "$at"
            recovery_ok=false
        fi
    elif [[ -f "$AUTH_ABSENT" && ! -e "$AUTH_FILE" ]]; then
        :
    fi

    if [[ -f "$SSHDIR_ABSENT" ]]; then
        rmdir /root/.ssh 2>/dev/null || recovery_ok=false
    elif [[ -f "$SSHDIR_STATE" && -d /root/.ssh ]]; then
        dir_mode="$(sed -n '1p' "$SSHDIR_STATE" 2>/dev/null || true)"
        dir_uid="$(sed -n '2p' "$SSHDIR_STATE" 2>/dev/null || true)"
        dir_gid="$(sed -n '3p' "$SSHDIR_STATE" 2>/dev/null || true)"
        [[ -z "$dir_mode" ]] || chmod "$dir_mode" /root/.ssh || recovery_ok=false
        if [[ -n "$dir_uid" && -n "$dir_gid" ]]; then
            chown "$dir_uid:$dir_gid" /root/.ssh 2>/dev/null || recovery_ok=false
        fi
    fi

    rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"

    if [[ -f "$HOSTKEY_LIST" ]]; then
        while IFS=$'\t' read -r hk private_id public_id; do
            [[ -n "$hk" ]] || continue
            current_private_id="$(hostkey_file_identity "$hk" 2>/dev/null || true)"
            current_public_id="$(hostkey_file_identity "${hk}.pub" 2>/dev/null || true)"
            if [[ -n "$private_id" && -n "$public_id" &&
                  "$current_private_id" == "$private_id" &&
                  "$current_public_id" == "$public_id" ]]; then
                rm -f "$hk" "${hk}.pub" || recovery_ok=false
            elif [[ -e "$hk" || -e "${hk}.pub" ]]; then
                logger -t ssh-algo-unified "HostKey 身份变化，跳过外部替换：$hk" 2>/dev/null || true
            fi
        done < "$HOSTKEY_LIST"
    fi

    if [[ -f "$CRYPTO_STATE" ]] && command -v update-crypto-policies >/dev/null 2>&1; then
        # 状态文件两行：1=本脚本写入值(比对基准)，2=测试前原值(恢复目标)。
        applied_policy="$(sed -n '1p' "$CRYPTO_STATE" 2>/dev/null || true)"
        old_policy="$(sed -n '2p' "$CRYPTO_STATE" 2>/dev/null || true)"
        cur_policy="$(update-crypto-policies --show 2>/dev/null || true)"
        # 仅当"当前值 == 本脚本写入的值"才恢复，避免覆盖他人修改。
        if [[ -n "$applied_policy" && -n "$old_policy" && "$cur_policy" == "$applied_policy" ]]; then
            update-crypto-policies --set "$old_policy" >/dev/null 2>&1 || recovery_ok=false
        fi
    fi

    logger -t ssh-algo-unified "检测到异常中止测试，已执行恢复" 2>/dev/null || true
    # ExecStartPre 场景下绝不能在自身内部 systemctl restart 同一个 unit，否则可能
    # 形成递归/事务冲突。恢复成功后让当前 service start 继续使用已恢复的配置。
    if $recovery_ok && $config_restored; then
        # 先验证恢复后的 sshd_config，再删除持久化状态；失败则保留 state，供下一次启动重试。
        if command -v sshd >/dev/null 2>&1 && sshd -t -f "$CONFIG" >/dev/null 2>&1; then
            if [[ "$HELPER_PREEXISTING" == true && -f "$HELPER_BACKUP" ]]; then
                mv -f "$HELPER_BACKUP" "$HELPER" || recovery_ok=false
            else
                rm -f "$HELPER"
            fi
            if [[ "$DROPIN_PREEXISTING" == true && -f "$DROPIN_BACKUP" ]]; then
                mv -f "$DROPIN_BACKUP" "$DROPIN" || recovery_ok=false
            else
                rm -f "$DROPIN"
            fi
            rm -f "$PIDFILE" "$BACKUP" "$AUTH_BACKUP" "$AUTH_ADDED" "$AUTH_ABSENT" "$AUTH_ACTIVE" "$HOSTKEY_LIST" "$CRYPTO_STATE" \
                "${BACKUP}.sshdir.absent" "${BACKUP}.sshdir.state"
        else
            recovery_ok=false
        fi
    else
        recovery_ok=false
    fi
    if $recovery_ok; then
        rmdir "$DROPIN_DIR" 2>/dev/null || true
        rm -rf /var/run/ssh-algo-unified.lock 2>/dev/null || true
        grep -lF 'ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT' \
            /etc/ssh/sshd_config.?????? /etc/ssh/sshd_config.restore.?????? \
            /etc/ssh/sshd_config.recover.?????? 2>/dev/null | xargs -r rm -f -- 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        exit 0
    fi
    logger -t ssh-algo-unified "恢复失败，保留状态文件并阻止 sshd 继续启动" 2>/dev/null || true
    exit 1
fi
exit 0
EOF
        then
            rm -f "$helper_tmp"
            log "[恢复] ERROR：无法写入 systemd 自愈脚本"
            return 1
        fi
        # here-doc 正文以待替换位置写成 @NAME@ 占位符，此处由 inject_helper_values
        # 用 awk 单次扫描精确注入真实值（值为单引号包裹的字面量）。
        if ! inject_helper_values "$helper_tmp"; then
            rm -f "$helper_tmp"
            log "[恢复] ERROR：无法注入自愈脚本变量"
            return 1
        fi
        if ! chmod 755 "$helper_tmp" ||
           ! backup_preexisting "$RESTORE_HELPER" ||
           ! mv -f "$helper_tmp" "$RESTORE_HELPER"; then
            rm -f "$helper_tmp"
            log "[恢复] ERROR：systemd 自愈脚本安装失败"
            return 1
        fi
        if ! mkdir -p "$SYSTEMD_DROPIN_DIR"; then
            log "[恢复] ERROR：无法创建 systemd drop-in 目录：$SYSTEMD_DROPIN_DIR"
            return 1
        fi
        if ! backup_preexisting "$SYSTEMD_DROPIN_FILE"; then
            log "[恢复] ERROR：无法备份 systemd drop-in：$SYSTEMD_DROPIN_FILE"
            return 1
        fi
        dropin_tmp="$(mktemp "${SYSTEMD_DROPIN_FILE}.XXXXXX")" || {
            log "[恢复] ERROR：无法创建 systemd recovery drop-in"
            return 1
        }
        if ! cat > "$dropin_tmp" <<EOF
# SSH algorithm unified test temporary recovery hook
[Service]
ExecStartPre=$RESTORE_HELPER
EOF
        then
            rm -f "$dropin_tmp"
            log "[恢复] ERROR：无法写入 systemd recovery drop-in"
            return 1
        fi
        if [[ -f /etc/crypto-policies/back-ends/opensslcnf.config ]]; then
            if ! printf '%s\n' 'Environment=OPENSSL_CONF=/etc/crypto-policies/back-ends/opensslcnf.config' >> "$dropin_tmp"; then
                rm -f "$dropin_tmp"
                log "[恢复] ERROR：无法写入 systemd drop-in 环境配置"
                return 1
            fi
        fi
        if ! mv -f "$dropin_tmp" "$SYSTEMD_DROPIN_FILE"; then
            rm -f "$dropin_tmp"
            log "[恢复] ERROR：无法安装 systemd recovery drop-in：$SYSTEMD_DROPIN_FILE"
            return 1
        fi
        if ! systemctl daemon-reload >/dev/null 2>&1; then
            log "[恢复] ERROR：systemd daemon-reload 失败，自愈未生效"
            return 1
        fi

    elif [[ "$INIT" == "sysv/service" && "$SERVICE" != "unknown" ]]; then
        if ! command -v crontab >/dev/null 2>&1; then
            # 降级而非中止：crontab 仅用于"崩溃后开机自愈"这一层兜底，
            # 它缺失并不影响正常测试流程（测试结束时的 restore_all 仍会
            # 完整恢复配置）。常见的精简容器/云镜像（AlmaLinux、openEuler
            # 基础镜像等）默认不带 cronie，若在此直接 return 1，会因
            # 调用点的 `|| die` 让整轮测试在开跑前就中止，属于过度严格。
            # 此处改为打印可操作提示并返回 0（视为"无需自愈"），继续测试。
            RECOVERY_SELFHEAL_UNAVAILABLE=true
            log "[恢复] WARNING：未找到 crontab，跳过 SysV 开机自愈安装（不影响本次测试与结束恢复）"
            log "[恢复] 提示：如需崩溃自愈，请安装 cronie 后重跑：yum install -y cronie  # 或 dnf install -y cronie"
            return 0
        fi
        local cron_tmp current helper_preexisting=false
        local helper_backup=""
        local grep_status=0
        helper_backup="${STATE_DIR}/preexisting_$(basename "$RESTORE_HELPER").$$"
        if [[ -e "$RESTORE_HELPER" ]]; then
            helper_preexisting=true
            RESTORE_HELPER_PREEXISTING=true
        fi
        local cron_list_rc=0
        current="$(crontab -l 2>/dev/null)" || cron_list_rc=$?
        if (( cron_list_rc != 0 && cron_list_rc != 1 )); then
            log "[恢复] ERROR：无法读取现有 crontab（状态码 $cron_list_rc）"
            return 1
        fi
        cron_tmp="$(mktemp "${TMP_DIR}/ssh-algo-unified-cron.XXXXXX")" || {
            log "[恢复] ERROR：无法创建 SysV 自愈 crontab 临时文件"
            return 1
        }
        grep_status=0
        grep -vF "$CRON_TAG" <<< "$current" > "$cron_tmp" || grep_status=$?
        if (( grep_status > 1 )); then
            rm -f "$cron_tmp"
            log "[恢复] ERROR：无法生成 SysV crontab 内容"
            return 1
        fi
        if ! printf '@reboot %s %s\n' "$RESTORE_HELPER" "$CRON_TAG" >> "$cron_tmp"; then
            rm -f "$cron_tmp"
            log "[恢复] ERROR：无法追加 SysV 自愈任务"
            return 1
        fi
        local helper_tmp
        helper_tmp="$(mktemp "${RESTORE_HELPER}.XXXXXX")" || die "无法创建恢复脚本"
        # 同 systemd 分支：<<'EOF' + 单 token 占位符，由 inject_helper_values
        # 注入单引号字面量，避免路径含 $ 时二次展开。
        if ! cat > "$helper_tmp" <<'EOF'
#!/bin/bash
set -u
CONFIG=@CONFIG@
BACKUP=@BACKUP@
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
SERVICE=@SERVICE@
INITIAL_SERVICE_KNOWN=@INITIAL_SERVICE_KNOWN@
INITIAL_SERVICE_ACTIVE=@INITIAL_SERVICE_ACTIVE@
PIDFILE=@PIDFILE@
AUTH_FILE=@AUTH_FILE@
HELPER=@HELPER@
HELPER_BACKUP=@HELPER_BACKUP@
HELPER_PREEXISTING=@HELPER_PREEXISTING@
AUTH_BACKUP="${BACKUP}.authkeys"
AUTH_ADDED="${BACKUP}.authkeys.added"
AUTH_ABSENT="${BACKUP}.authkeys.absent"
AUTH_ACTIVE="${BACKUP}.authkeys.active"
SSHDIR_ABSENT="${BACKUP}.sshdir.absent"
SSHDIR_STATE="${BACKUP}.sshdir.state"
HOSTKEY_LIST=@HOSTKEY_LIST@
CRYPTO_STATE=@CRYPTO_STATE@
AUTO_KEY=@AUTO_KEY@
AUTO_PUB=@AUTO_PUB@
AUTO_SSH1_KEY=@AUTO_SSH1_KEY@
AUTO_SSH1_PUB=@AUTO_SSH1_PUB@

hostkey_file_identity() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        ssh-keygen -lf "$file" 2>/dev/null | awk 'NR == 1 {print $2}'
    fi
}

recovery_ok=true
config_restored=false
if [[ -f "$BACKUP" ]] && grep -qF "$MARKER" "$CONFIG" 2>/dev/null; then
    t="$(mktemp "${CONFIG}.recover.XXXXXX")"
    if cp -a "$BACKUP" "$t" && mv -f "$t" "$CONFIG"; then
        config_restored=true
    else
        rm -f "$t"
        recovery_ok=false
    fi
else
    recovery_ok=false
fi
if [[ -f "$AUTH_ADDED" && -e "$AUTH_FILE" ]]; then
    at="$(mktemp "${BACKUP}.authkeys.recover.XXXXXX" 2>/dev/null || true)"
    if [[ -n "$at" ]] &&
       { grep -Fvxf "$AUTH_ADDED" "$AUTH_FILE" > "$at" || [[ $? -eq 1 ]]; } &&
       chmod 600 "$at" && mv -f "$at" "$AUTH_FILE"; then
        :
    else
        rm -f "$at"
        recovery_ok=false
    fi
elif [[ -f "$AUTH_ABSENT" && ! -e "$AUTH_FILE" ]]; then
    :
fi
if [[ -f "$HOSTKEY_LIST" ]]; then
    while IFS=$'\t' read -r hk private_id public_id; do
        [[ -n "$hk" ]] || continue
        current_private_id="$(hostkey_file_identity "$hk" 2>/dev/null || true)"
        current_public_id="$(hostkey_file_identity "${hk}.pub" 2>/dev/null || true)"
        if [[ -n "$private_id" && -n "$public_id" &&
              "$current_private_id" == "$private_id" &&
              "$current_public_id" == "$public_id" ]]; then
            rm -f "$hk" "${hk}.pub" || recovery_ok=false
        elif [[ -e "$hk" || -e "${hk}.pub" ]]; then
            logger -t ssh-algo-unified "HostKey 身份变化，跳过外部替换：$hk" 2>/dev/null || true
        fi
    done < "$HOSTKEY_LIST"
fi
if [[ -f "$CRYPTO_STATE" ]] && command -v update-crypto-policies >/dev/null 2>&1; then
    # 状态文件两行：1=本脚本写入值(比对基准)，2=测试前原值(恢复目标)。
    applied_policy="$(sed -n '1p' "$CRYPTO_STATE" 2>/dev/null || true)"
    old_policy="$(sed -n '2p' "$CRYPTO_STATE" 2>/dev/null || true)"
    cur_policy="$(update-crypto-policies --show 2>/dev/null || true)"
    if [[ -n "$applied_policy" && -n "$old_policy" && "$cur_policy" == "$applied_policy" ]]; then
        update-crypto-policies --set "$old_policy" >/dev/null 2>&1 || recovery_ok=false
    fi
fi
if [[ -f "$SSHDIR_ABSENT" ]]; then
    rmdir /root/.ssh 2>/dev/null || recovery_ok=false
elif [[ -f "$SSHDIR_STATE" && -d /root/.ssh ]]; then
    dir_mode="$(sed -n '1p' "$SSHDIR_STATE" 2>/dev/null || true)"
    dir_uid="$(sed -n '2p' "$SSHDIR_STATE" 2>/dev/null || true)"
    dir_gid="$(sed -n '3p' "$SSHDIR_STATE" 2>/dev/null || true)"
    [[ -z "$dir_mode" ]] || chmod "$dir_mode" /root/.ssh || recovery_ok=false
    if [[ -n "$dir_uid" && -n "$dir_gid" ]]; then
        chown "$dir_uid:$dir_gid" /root/.ssh 2>/dev/null || recovery_ok=false
    fi
fi
rm -f "$AUTO_KEY" "$AUTO_PUB" "$AUTO_SSH1_KEY" "$AUTO_SSH1_PUB"
if [[ $recovery_ok && $config_restored ]]; then
    if command -v sshd >/dev/null 2>&1; then
        sshd -t -f "$CONFIG" >/dev/null 2>&1 || recovery_ok=false
    else
        recovery_ok=false
    fi
fi
if [[ $recovery_ok && $config_restored ]] && [[ "$INITIAL_SERVICE_KNOWN" == true ]]; then
    if [[ "$INITIAL_SERVICE_ACTIVE" == true ]]; then
        service "$SERVICE" restart >/dev/null 2>&1 || recovery_ok=false
    else
        service "$SERVICE" stop >/dev/null 2>&1 || recovery_ok=false
    fi
fi
if [[ $recovery_ok && $config_restored ]]; then
    rm -f "$AUTH_BACKUP" "$AUTH_ADDED" "$AUTH_ABSENT" "$AUTH_ACTIVE" "$HOSTKEY_LIST" "$CRYPTO_STATE" \
        "${BACKUP}.sshdir.absent" "${BACKUP}.sshdir.state"
fi
if [[ $recovery_ok && $config_restored ]]; then
    if [[ "$HELPER_PREEXISTING" == true && -f "$HELPER_BACKUP" ]]; then
        mv -f "$HELPER_BACKUP" "$HELPER" || recovery_ok=false
    else
        rm -f "$HELPER"
    fi
    rm -f "$PIDFILE" "$BACKUP" 2>/dev/null || true
    exit 0
fi
logger -t ssh-algo-unified "SysV 恢复失败，保留状态文件供下次开机重试" 2>/dev/null || true
exit 1
EOF
        then
            rm -f "$helper_tmp" "$cron_tmp"
            log "[恢复] ERROR：无法写入 SysV 自愈脚本"
            return 1
        fi
        if ! inject_helper_values "$helper_tmp"; then
            rm -f "$helper_tmp" "$cron_tmp"
            log "[恢复] ERROR：无法注入自愈脚本变量"
            return 1
        fi
        if ! chmod 755 "$helper_tmp" ||
           ! backup_preexisting "$RESTORE_HELPER" ||
           ! mv -f "$helper_tmp" "$RESTORE_HELPER"; then
            rm -f "$helper_tmp" "$cron_tmp"
            log "[恢复] ERROR：SysV 自愈脚本安装失败"
            return 1
        fi
        if ! crontab "$cron_tmp" 2>/dev/null; then
            rm -f "$cron_tmp"
            log "[恢复] ERROR：SysV crontab 自愈任务安装失败"
            return 1
        fi
        rm -f "$cron_tmp"
    else
        log "[恢复] ERROR：没有可用的崩溃自愈安装方式（INIT=$INIT SERVICE=$SERVICE）"
        return 1
    fi
}

# 恢复钩子：INT/TERM 保留传统信号退出码（130/143）；EXIT 钩子根据
# restore_all 的返回码决定最终退出码。restore_all 内部不再 exit，避免
# 改写调用点已确定的退出码或与 EXIT trap 叠加递归。
trap 'restore_all || true; exit 130' INT
trap 'restore_all || true; exit 143' TERM
# EXIT：保留调用点已确定的退出码；若 restore_all 报告恢复失败，则强制非零，
# 保证"sshd 未完整恢复"时脚本不会以 0 退出。
trap 'rc=$?; restore_all || rc=$RESTORE_EXIT_CODE; [[ "$rc" -eq 0 && "$RESTORE_EXIT_CODE" -ne 0 ]] && rc=$RESTORE_EXIT_CODE; exit "$rc"' EXIT

acquire_lock || exit 1

record_initial_state
backup_config
# 自愈安装失败不再中止整轮测试：自愈只是"崩溃/断电后的开机兜底"，
# 缺失它并不影响本次测试的正确性（结束时的 restore_all 仍会完整恢复）。
# 若因 crontab 缺失、drop-in 目录不可写等原因安装失败，降级为警告继续，
# 但把状态记录下来，便于结束时在恢复报告里如实提示。
if ! install_recovery; then
    RECOVERY_SELFHEAL_UNAVAILABLE=true
    log "[错误] 崩溃自愈安装失败，已降级为无自愈模式继续测试（结束后仍会正常恢复配置）"
fi

# crypto-policy 与 HostKey 必须在动态候选/组合探测之前准备完成。
prepare_crypto_policy
prepare_host_keys

case "$PROFILE" in
    modern)
        load_dynamic_tests
        ;;
    centos6)
        load_centos6_tests
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

if $AUTO; then
    prepare_auto_key || die "无法准备自动模式临时认证密钥"
fi


compute_overall() {
    # 把协商/认证/命令/客户端四维结果合并为单一总体结果。
    # 该判定口径原先在 write_result、record_result、test_one 三处各写一份，
    # 一旦其中一处改动而其它处未同步，就会出现"日志显示 PASS、计数却是
    # COMMAND_FAIL"这类自相矛盾（第六轮审查 F3 即此问题）。收敛为唯一实现，
    # 所有调用点共享同一口径，杜绝再次漂移。
    local nr="$1" ar="$2" er="$3" cpr="$4" overall="$1"
    if [[ "$nr" == "PASS" ]]; then
        if [[ "$ar" == "FAIL" ]]; then
            overall="AUTH_FAIL"
        elif [[ "$ar" == "PASS" && "$er" == "PASS" && "$cpr" == "PASS" ]]; then
            overall="PASS"
        elif [[ "$ar" == "PASS" && "$er" == "FAIL" ]]; then
            overall="COMMAND_FAIL"
        elif [[ "$ar" == "PASS" && "$cpr" == "FAIL" ]]; then
            overall="CLIENT_FAIL"
        else
            overall="UNKNOWN"
        fi
    fi
    printf '%s' "$overall"
}

write_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" default_supported="${16}" reason="${17}"
    local er="${RESULT_COMMAND:-UNKNOWN}" cpr="${RESULT_CLIENT_PROCESS:-UNKNOWN}"
    local result_compression="${RESULT_COMPRESSION:-N/A}"
    local actual_compression="${RESULT_COMPRESSION_ACTUAL:-UNKNOWN}"
    [[ "$actual_compression" == "UNKNOWN" && "$nr" != "PASS" ]] &&
        actual_compression="N/A (not negotiated)"

    local fm_report="$fm"
    case "$fc" in
        chacha20-poly1305@openssh.com|aes128-gcm@openssh.com|aes256-gcm@openssh.com)
            fm_report="AEAD/N (no traditional MAC)"
            ;;
    esac

    local overall
    overall="$(compute_overall "$nr" "$ar" "$er" "$cpr")"

    log ""
    log "-------------------- 测试结果 --------------------"
    log "测试项         : #${idx} ${desc}"
    log "测试组         : ${group}"
    log "协议           : SSH-${proto}"
    log "固定 Protocol  : SSH-${proto}"
    log "固定 KEX       : $([[ "$proto" == "1" ]] && echo N/A || echo "${fk:-UNKNOWN}")"
    log "固定 Cipher    : ${fc:-UNKNOWN}"
    log "固定 MAC       : $([[ "$proto" == "1" ]] && echo N/A || echo "${fm_report:-UNKNOWN}")"
    log "固定 HostKey   : $([[ "$proto" == "1" ]] && echo RSA1 || echo "${fh:-UNKNOWN}")"
    log "固定 Compression: ${result_compression}"
    log "实际 KEX       : $([[ "$proto" == "1" ]] && echo N/A || echo "${nk:-UNKNOWN}")"
    log "实际 Cipher    : ${nc:-UNKNOWN}"
    log "实际 MAC       : $([[ "$proto" == "1" ]] && echo N/A || echo "${nm:-UNKNOWN}")"
    log "实际 HostKey   : ${nh:-UNKNOWN}"
    log "实际 Compression: ${actual_compression}"
    log "协商结果 NR    : ${nr}"
    log "认证结果 AR    : ${ar}"
    log "命令执行结果 ER: ${er}"
    log "客户端进程 CPR : ${cpr}"
    log "客户端诊断 CR  : ${cr}"
    log "默认配置支持   : ${default_supported}"
    if [[ "$group" == *"SERVER-FILTER/UNSUPPORTED"* ]] || [[ "$cr" == "SERVER_UNSUPPORTED" ]]; then
        log "Server Filter   : UNSUPPORTED"
    elif [[ "$group" == *"SERVER-FILTER/UNKNOWN/PRECHECK_ERROR"* ]]; then
        log "Server Filter   : UNKNOWN/PRECHECK_ERROR"
    else
        log "Server Filter   : NONE"
    fi
    log "总体结果       : ${overall}"
    [[ -n "$reason" ]] && log "原因           : ${reason}"
    log "---------------------------------------------------"
}

should_run() {
    local idx="$1"
    local desc="$2"

    [[ -z "$ONLY_FILTER" ]] && return 0

    if [[ "$ONLY_FILTER" =~ ^[0-9]+$ ]]; then
        [[ "$((10#$idx))" == "$((10#$ONLY_FILTER))" ]]
        return
    fi

    # shopt 是全局设置。在子 shell 里开 nocasematch 做大小写不敏感匹配，
    # 保证即使中途出错（set -e / 信号）也不会把 nocasematch 泄漏到后续
    # 逻辑（否则配置匹配、marker 检测等会意外变成大小写不敏感）。
    ( shopt -s nocasematch; [[ "$desc" == *"$ONLY_FILTER"* ]] )
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
        # TEST_START_TIME 通常由调用方 test_one() 以 local 定义并通过 bash
        # 动态作用域可见。这里显式兜底，避免将来在 test_one 之外调用本函数
        # 时因 set -u 报 unbound variable；无时间戳时回退到最近 5 分钟。
        local since="${TEST_START_TIME:-}"
        [[ -n "$since" ]] || since="$(date -d '5 minutes ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
        if [[ -n "$since" ]]; then
            journalctl -u "${unit}.service" --since "$since" --no-pager -o short-iso 2>/dev/null || true
        else
            journalctl -u "${unit}.service" --no-pager -o short-iso 2>/dev/null || true
        fi
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
    local file="$1" size="$2" delta
    # 最多轮询 5 次；循环变量仅作计数，不参与后续判断，故不声明具名变量。
    for _ in 1 2 3 4 5; do
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
    local file="$1" size="$2"
    local max_wait="${MANUAL_WAIT_MAX:-600}"
    # 检测到外部客户端连接后，继续采集日志的时长（默认 1800 秒 = 30 分钟）。
    # 目的：连接一旦建立即持续采集协商/认证/会话日志增量，确保证据完整落盘，
    # 而不是刚看到"kex: "就急着结束。该时长计入 max_wait 总预算：当
    # waited 达到 max_wait 时无论是否采满都会结束，避免超出用户设定的上限。
    # 若在采集期间拿到明确结束证据（terminal_seen），则立即结束，无需等满。
    local post_detect_wait="${MANUAL_POST_CONNECT_WAIT:-1800}"
    local waited=0
    local connected=false
    local connected_at=-1
    local connection_pid=""
    local acc=""
    local terminal_seen=false
    local journal_seen=0
    # extra 此前未声明为 local，每次循环赋值都会污染同名全局变量（若外部
    # 存在该名字会被意外覆盖）。显式声明为局部变量。
    local extra=""

    if [[ -z "$file" ]]; then
        log "警告：未找到服务端日志文件，无法等待外部客户端连接；本项按当前状态记录。"
        return 0
    fi

    log "等待外部客户端连接（最多 ${max_wait} 秒；连接后最多再采集 ${post_detect_wait} 秒日志）"

    while (( waited < max_wait )); do
        local d="" full="" total=0
        if [[ "$file" == JOURNAL:* ]]; then
            full="$(read_log_delta "$file" "$size")"
            total="$(printf '%s\n' "$full" | grep -c '.' || true)"
            if (( total > journal_seen )); then
                d="$(printf '%s\n' "$full" | tail -n "+$((journal_seen + 1))")"
                journal_seen="$total"
            fi
        else
            d="$(read_log_delta "$file" "$size")"
        fi

        if [[ "$file" != JOURNAL:* ]]; then
            local cur_size
            cur_size="$(file_size "$file")"
            if (( cur_size != size )); then
                size="$cur_size"
            fi
        fi

        if [[ -n "$d" ]]; then
            if ! $connected; then
                if printf '%s\n' "$d" | grep -qiE \
                    'kex: |server->client|Offering |Accepted password|Accepted publickey|PAM: authentication|kex_exchange_identification|Unable to negotiate|no matching'; then
                    connected=true
                    connected_at=$waited
                    connection_pid="$(printf '%s\n' "$d" |
                        sed -n 's/.*sshd\[\([0-9][0-9]*\)\].*/\1/p' | head -1)"
                    if [[ -n "$connection_pid" ]]; then
                        log "已检测到外部客户端连接（sshd PID=${connection_pid}）；继续采集日志，最多 ${post_detect_wait} 秒。"
                    else
                        log "已检测到外部客户端连接（日志无 PID，使用本次增量）；继续采集日志，最多 ${post_detect_wait} 秒。"
                    fi
                fi
            fi

            if $connected; then
                local relevant="$d"
                if [[ -n "$connection_pid" ]]; then
                    relevant="$(printf '%s\n' "$d" | grep -F "sshd[${connection_pid}]" || true)"
                fi
                if [[ -n "$relevant" ]]; then
                    acc+="$relevant"$'\n'
                    if printf '%s\n' "$relevant" | grep -qiE \
                        'Unable to negotiate|no matching .*found|no matching .*method|Protocol major versions differ|Failed password|Failed publickey|Failed none|authentication failure|Connection closed|Received disconnect|Disconnected from|session closed|Close session'; then
                        terminal_seen=true
                    fi
                fi
            fi
        fi

        if $connected && $terminal_seen; then
            # 再留一个轮询周期，让 Worker 的最后 session/exec 日志落盘。
            sleep 2
            # read_log_delta 内部已区分 JOURNAL:* 与普通文件，此处无需再分叉。
            extra="$(read_log_delta "$file" "$size")"
            if [[ -n "$extra" ]]; then
                if [[ -n "$connection_pid" ]]; then
                    extra="$(printf '%s\n' "$extra" | grep -F "sshd[${connection_pid}]" || true)"
                fi
                [[ -n "$extra" ]] && acc+="$extra"$'\n'
            fi
            log "已采集到本次连接的结束/失败证据，结束当前 TEST_CASE 日志采集。"
            printf '%s' "$acc"
            return 0
        fi

        # 连接已建立且持续采集达到 post_detect_wait 时长，结束采集。
        if $connected && (( connected_at >= 0 )) &&
           (( waited - connected_at >= post_detect_wait )); then
            log "已检测到连接并持续采集满 ${post_detect_wait} 秒，结束当前 TEST_CASE 日志采集。"
            printf '%s' "$acc"
            return 0
        fi

        sleep 2
        waited=$((waited + 2))
    done

    if $connected; then
        log "外部客户端连接已检测到，但未在 ${max_wait} 秒内观察到明确结束证据；按已采集日志判定本项。"
    else
        log "等待外部客户端连接超时（${max_wait} 秒），本项按当前状态记录并继续。"
    fi
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

extract_negotiated_compression() {
    local text="$1" value=""
    value="$(printf '%s\n' "$text" |
        grep -m1 -E 'compression: (none|zlib@openssh\.com|zlib)' |
        sed -nE 's/.*compression: (none|zlib@openssh\.com|zlib).*/\1/p' |
        head -1 | tr -d '\r')"
    if [[ "$value" != "none" && "$value" != "zlib" && "$value" != "zlib@openssh.com" ]]; then
        # 旧式日志回退（OpenSSH 5.x / CentOS 6）：形如
        #   debug1: kex: server->client blowfish-cbc hmac-sha1 none
        # 压缩算法是行尾最后一个字段。注意：Windows/CRLF 场景下该行以 \r 结尾，
        # 若正则用 "$" 锚定行尾，\r 会让匹配失败——必须先剔除 \r 再匹配，
        # 故这里用 tr -d '\r' 预处理，最后以 awk 取 $NF。
        value="$(printf '%s\n' "$text" | tr -d '\r' |
            grep -m1 -E 'kex: server->client .* (none|zlib@openssh\.com|zlib)$' |
            awk '{print $NF}')"
    fi
    printf '%s' "$value"
}

extract_negotiated_hostkey() {
    local text="$1"
    # 依次尝试多种日志形态（取第一条命中的）：
    #   1) debug1: kex: host key algorithm: ssh-ed25519        （现代 OpenSSH 主形态）
    #   2) ...host key algorithm: rsa-sha2-512                 （容错无 kex: 前缀的情况）
    #   3) debug1: Server host key: ssh-ed25519 SHA256:xxx     （兜底；首字母固定大写 S）
    #   4) debug1: list_hostkey_types: ssh-rsa                 （OpenSSH 5.x 旧式服务端）
    # 第 3 条必须写成 "Server host key"（大写 S），OpenSSH 该行首字母就是大写；
    # 早期此规则误写为全小写，grep/sed 均大小写敏感，导致该兜底分支永远匹配不到，
    # 主路径失效时 NH 会解析为空。此处按实际形态修正。
    # 第 4 条：OpenSSH < 6（如 CentOS 6 的 5.3）客户端完全不打印 hostkey，
    # 其服务端 DEBUG3 只输出 "list_hostkey_types: <algo>"；这是旧版唯一可得的
    # hostkey 证据，缺了它会让 5.x 上所有 SSH-2 项的 NH 恒为 UNKNOWN。
    printf '%s\n' "$text" |
        grep -m1 -E 'kex: host key algorithm: |host key algorithm: |Server host key|list_hostkey_types:' |
        sed -nE \
            -e 's/.*kex: host key algorithm:[[:space:]]*([^[:space:]\r]+).*/\1/p' \
            -e 's/.*host key algorithm:[[:space:]]*([^[:space:]\r]+).*/\1/p' \
            -e 's/.*Server host key[[:space:]:]+([^[:space:]\r]+).*/\1/p' \
            -e 's/.*list_hostkey_types:[[:space:]]*([^[:space:]\r]+).*/\1/p' |
        head -1 | tr -d '\r'
}

# 使用 sshd -Q 做“理论能力预检”，使用 sshd -T 做“最终配置预检”。
# 预检只用于诊断/筛选；完整组合预检失败时，该 TEST_CASE 仍保留并记录为 NEGOTIATION_FAIL。
SUPPORTED_KEX=""
SUPPORTED_CIPHER=""
SUPPORTED_MAC=""
SUPPORTED_HOSTKEY=""
EFFECTIVE_KEX=""
EFFECTIVE_CIPHER=""
EFFECTIVE_MAC=""
EFFECTIVE_HOSTKEY=""
EFFECTIVE_HOSTKEY_ALGORITHMS=""
EFFECTIVE_COMPRESSION=""
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
    EFFECTIVE_COMPRESSION=""

    [[ -n "$SSHD_BIN" && -f "$config" ]] || return 2
    output="$("$SSHD_BIN" -T -f "$config" 2>/dev/null)" || return 1

    EFFECTIVE_KEX="$(printf '%s\n' "$output" | awk '$1 == "kexalgorithms" { print $2 }' | tr ',' '\n')"
    EFFECTIVE_CIPHER="$(printf '%s\n' "$output" | awk '$1 == "ciphers" { print $2 }' | tr ',' '\n')"
    EFFECTIVE_MAC="$(printf '%s\n' "$output" | awk '$1 == "macs" { print $2 }' | tr ',' '\n')"
    # OpenSSH 5.x 的 -T 输出是 hostkey 文件路径；现代版本也可能输出
    # hostkey 路径，因此统一保留路径，algo_effective_supported 再映射算法名。
    EFFECTIVE_HOSTKEY="$(printf '%s\n' "$output" | awk '$1 == "hostkey" { print $2 }')"
    EFFECTIVE_HOSTKEY_ALGORITHMS="$(printf '%s\n' "$output" | awk '$1 == "hostkeyalgorithms" { print $2 }' | tr \, '\n')"
    EFFECTIVE_COMPRESSION="$(printf '%s\n' "$output" | awk '$1 == "compression" { print $2 }')"

    env_log "sshd -T -f $config: available"
    return 0
}

algo_effective_supported() {
    local type="$1" algo="$2" list=""
    [[ -n "$algo" ]] || return 0
    # 仅当本机 sshd 不支持 KexAlgorithms 时才跳过 KEX 生效性断言
    #（真正的旧 5.x 上游版：其 -T 不输出 kexalgorithms，EFFECTIVE_KEX 恒空）。
    # CentOS 6 的 5.3p1 回溯支持该指令，-T 会输出 kexalgorithms，故正常断言。
    # 注意：ciphers/macs 无需放宽——只要测试配置显式写了 "Ciphers/MACs"，
    # -T 就会输出对应行，校验始终有效。
    if [[ "$type" == "kex" ]] && ! sshd_supports_kex_algorithms; then
        return 0
    fi
    case "$type" in
        kex) list="$EFFECTIVE_KEX" ;;
        cipher) list="$EFFECTIVE_CIPHER" ;;
        mac) list="$EFFECTIVE_MAC" ;;
        key)            # 新版 OpenSSH 直接验证 HostKeyAlgorithms；CentOS 6/OpenSSH 5.3
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
        compression)
            # sshd -T 将 "Compression yes" 与 "Compression delayed" 统一输出为
            # "compression yes"。因此 zlib@openssh.com（延迟压缩）在这一层只能
            # 校验到 "yes"；若坚持要求 "delayed" 会把合法项误判为未启用。
            # 反向兼容：OpenSSH < 6（CentOS 6 的 5.3）的 -T 直接输出
            # "compression delayed" 而非 "yes"，故 yes 与 delayed 都接受。
            case "$algo" in
                none) [[ "$EFFECTIVE_COMPRESSION" == "no" ]] ;;
                zlib|zlib@openssh.com) [[ "$EFFECTIVE_COMPRESSION" == "yes" || "$EFFECTIVE_COMPRESSION" == "delayed" ]] ;;
                *) return 1 ;;
            esac
            return
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
        # 默认强制只监听回环地址：测试期间会临时放开 PermitRootLogin /
        # PasswordAuthentication，必须同时收窄监听范围，避免这些弱配置
        # 对非本机可见。仅当显式 --allow-remote 时才放开（隔离网络专用）。
        if ! $ALLOW_REMOTE; then
            printf '%s\n' 'ListenAddress 127.0.0.1'
        fi
        if [[ "$proto" == "1" ]]; then
            # SSH-1 cipher 的服务端写法随版本变化，必须按版本选择：
            #   * OpenSSH < 6（如 CentOS 6 的 5.3）根本没有 "Cipher" 配置项，
            #     仅认 "Ciphers" 且只校验 SSH-2 名称——因此 5.x 无法通过配置
            #     限制 SSH-1 cipher，写 "Cipher" 会直接 "Bad configuration
            #     option" 使整个测试项无法启动。此版本下不写 cipher 指令，
            #     由客户端 `ssh -1 -c <cipher>` 端指定（见 run_auto_ssh1）。
            #   * OpenSSH 6.0 ~ 7.5 保留 SSH-1，且提供 "Cipher"（单数）
            #     作为 SSH-1 cipher 选择项，此时才写入。
            #   * OpenSSH >= 7.6 已彻底移除 SSH-1（protocol 2 only），不会走到
            #     本节（SSH-1 测试项在上游已被 SSH-1 能力探测过滤）。
            printf '%s\n' \
                'Protocol 1' \
                'PermitRootLogin yes' \
                'PasswordAuthentication yes' \
                'RSAAuthentication yes' \
                'UsePAM yes'
            if [[ -n "$SSHD_VER_MAJOR" ]] && (( SSHD_VER_MAJOR >= 6 )); then
                printf '%s\n' "Cipher ${ssh1cipher}"
            fi
            printf '%s\n' \
                "Compression $([[ "$compression" == "zlib" ]] && echo yes || echo no)" \
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
                "Ciphers ${cipher}" \
                'LogLevel DEBUG3'
            # KexAlgorithms 自 OpenSSH 6.1 才存在；5.x 写入会 "Bad
            # configuration option"。5.x 无法固定 KEX（客户端同样无
            # -o KexAlgorithms），由编译期默认顺序决定，断言处亦相应放宽。
            if sshd_supports_kex_algorithms; then
                printf '%s\n' "KexAlgorithms ${kex}"
            fi
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
            local hostkey_file
            hostkey_file="$(hostkey_private_file "$hostkey" 2>/dev/null || printf '%s\n' /etc/ssh/ssh_host_rsa_key)"
            printf '%s\n' "HostKey $hostkey_file"
        fi
        printf '%s\n' '# --- END UNIFIED TEST OVERRIDES ---'
    } > "$tmp"

    # 原配置全部保留；仅注释全局范围内与本次测试直接冲突的指令。
    awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; print; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1 }
        {
            if ($0 ~ /^[[:space:]]*(Protocol|KexAlgorithms|Ciphers|Cipher|MACs|HostKeyAlgorithms|HostKey|Include)[[:space:]]+/ ||
                (!in_match && $0 ~ /^[[:space:]]*(Port|ListenAddress|LogLevel|Compression)[[:space:]]+/)) {
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
    local idx="$1" desc="$2" cipher="$3" target="$4" compression="${5:-none}"
    local cfg_content
    cfg_content="$(make_test_config_from_backup 1 "$idx" "$desc" "" "" "" "" "$cipher" "$compression")" || return 1
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
    local hostkey_pinned=false
    if [[ "$SSH_VER" =~ ^[0-9]+\. ]] && {
        (( ${SSH_VER%%.*} > 6 )) ||
        { [[ "$SSH_VER" =~ ^6\. ]] && (( ${SSH_VER#6.} >= 5 )); };
    }; then
        hostkey_opt="-o HostKeyAlgorithms=$hostkey"
        hostkey_pinned=true
    fi

    # 现代 OpenSSH 里 HostKeyAlgorithms 与 PubkeyAcceptedAlgorithms 是联动的：
    # 某些发行版（典型如 openEuler 的 crypto-policy）会把 ssh-rsa/ssh-dss/sm2
    # 这类算法从默认的 PubkeyAcceptedAlgorithms 中剔除。此时仅在命令行写
    # "HostKeyAlgorithms=X" 会让客户端的初始 KEXINIT 主机密钥候选被交集清空，
    # 于是 debug 出现 "kex: host key algorithm: (no match)"，服务端日志记
    # "no matching host key type found ... Their offer: "（offer 为空），
    # 白白把一次本应成功的协商记成 NEGOTIATION_FAIL。
    # 解决方式：固定了某个 HostKey 算法时，用 "PubkeyAcceptedAlgorithms=+X"
    # 把它追加回候选（+ 保留其余默认值，不会排除其它算法）。
    # 该选项自 OpenSSH 8.5 起才存在，故仅在客户端版本足够新时追加；sshd 侧
    # 的 HostKeyAlgorithms 仍旧单独固定，语义不变。
    local pubkey_opt=""
    if [[ "$hostkey_pinned" == true && -n "$hostkey" && -n "$SSH_VER_MAJOR" ]] &&
        { (( SSH_VER_MAJOR > 8 )) || { (( SSH_VER_MAJOR == 8 )) && (( SSH_VER_MINOR >= 5 )); }; }; then
        pubkey_opt="-o PubkeyAcceptedAlgorithms=+$hostkey"
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
        -F /dev/null \
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
        $pubkey_opt \
        $comp_opt \
        -p "$PORT" "$LOOPBACK_TARGET" true \
        >"$output" 2>&1
}

run_auto_ssh1() {
    local cipher="$1" output="$2" compression="${3:-none}"

    # SSH-1 自动模式也用临时公钥做 RSA 认证（与 SSH-2 一致），
    # 避免 BatchMode=yes + 无密码导致认证必失败。
    local identity_opt=""
    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR >= 6 )); then
        identity_opt="-o IdentitiesOnly=yes"
    fi

    # 用数组承载可选的 -C 参数，避免 $() 未加引号导致的 word splitting
    # （SC2046）；直接加引号则会在不需要时传入空参数，故用数组最稳妥。
    #
    # 关键兼容性：本脚本开头启用了 `set -u`。在 **bash 4.1**（CentOS 6 自带
    # 4.1.2）下，对"已声明但为空"的数组用 `"${arr[@]}"` 展开会触发
    # `arr[@]: unbound variable` 并使命令**整体失败**（bash 4.4+ 才修正为
    # 正常展开为 0 个参数）。当 compression=none 时 comp_arg 恰为空数组，
    # 于是 ssh 命令因展开报错根本没执行、输出为空、rc=1，被误判为
    # CLIENT_EXIT_1 —— 这正是"SSH-1 的 none 压缩项全失败、zlib 项全通过"的根因。
    # 修复：用 `${arr[@]+"${arr[@]}"}` 惯用法，空数组时不展开、非空时正常展开，
    # 在 bash 4.1 与 5.x 下行为一致。
    local comp_args=()
    [[ "$compression" == "zlib" ]] && comp_args=(-C)

    ssh -vvv -1 \
        -F /dev/null \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=1 \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        $identity_opt \
        -i "$AUTO_SSH1_KEY" \
        -p "$PORT" \
        ${comp_args[@]+"${comp_args[@]}"} \
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
} | tee -a "$LOG_FILE"

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
            if ! service_restart >/dev/null 2>&1; then
                log "[恢复] ERROR：$reason：sshd 无法恢复为运行状态"
                RESTORE_FAILED=true
            fi
        else
            local stop_ok=true
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || stop_ok=false
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || stop_ok=false
            fi
            $stop_ok || { log "[恢复] ERROR：$reason：无法恢复 sshd 为测试前停止状态"; RESTORE_FAILED=true; }
        fi
    fi

    rm -f "$TMP_DIR"/algo_client.* "$TMP_DIR"/algo_sshd_t.* \
        "$TMP_DIR"/ssh_algo_probe.* "$TMP_DIR"/ssh_algo_single.* "$TMP_DIR"/ssh1probe.* 2>/dev/null || true
}

record_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" reason="${16}"
    # 类型B（默认配置）标记：从 DEFAULT_FLAGS 按编号取，调用点无需改动。
    local default_supported="${DEFAULT_FLAGS[$((idx - 1))]:-n/a}"

    local er="${RESULT_COMMAND:-UNKNOWN}" cpr="${RESULT_CLIENT_PROCESS:-UNKNOWN}"
    local overall
    overall="$(compute_overall "$nr" "$ar" "$er" "$cpr")"

    case "$overall" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        AUTH_FAIL|COMMAND_FAIL|CLIENT_FAIL|FAIL) FAIL=$((FAIL + 1)) ;;
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
    local precheck_status="${PRECHECK_STATUS[$p]:-PASS}"
    local precheck_reason="${PRECHECK_REASON[$p]:-}"

    should_run "$idx" "$desc" || return 0

    RESULT_COMPRESSION="$compression"
    RESULT_COMPRESSION_ACTUAL="UNKNOWN"
    RESULT_COMMAND="NOT_RUN"
    RESULT_CLIENT_PROCESS="NOT_RUN"

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
    [[ "$proto" == "1" ]] && { NK="N/A"; NM="N/A"; NH="UNKNOWN"; }

    local NR="UNKNOWN"
    local AR="UNKNOWN"
    local CR="UNKNOWN"

    log ""
    log "============================================================"
    log "[协商测试] #${idx} ${desc}"
    if [[ "$proto" == "1" ]]; then
        log "固定：Protocol=1 Cipher=${cipher} RSA1 HostKey=${hostkey} Compression=${compression}"
    else
        log "固定：Protocol=2 KEX=${kex} Cipher=${cipher} MAC=${mac:-N/A} HostKey=${hostkey} Compression=${compression}"
    fi

    # 完整组合预检明确失败：该组合就是 NEGOTIATION_FAIL TEST_CASE，
    # 保留结果并继续下一个组合，不再改写真实 sshd 配置。
    if [[ "$proto" == "2" && "$precheck_status" == "FAIL" ]]; then
        NR="FAIL"
        AR="NOT_TESTED"
        CR="NEGOTIATION_FAIL"
        reason="${precheck_reason:-服务器组合配置校验失败}"
        log "组合预检：FAIL"
        log "原因：$reason"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey"             "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        return 0
    fi
    if [[ "$proto" == "2" && "$precheck_status" == "UNSUPPORTED" ]]; then
        NR="FAIL"
        AR="NOT_TESTED"
        CR="SERVER_UNSUPPORTED"
        reason="${precheck_reason:-Server Filter 判定为 UNSUPPORTED}"
        log "Server Filter：UNSUPPORTED"
        log "原因：$reason"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        return 0
    fi
    if [[ "$proto" == "2" && "$precheck_status" == "UNKNOWN" &&
          "$group" == *"SERVER-FILTER/UNKNOWN/PRECHECK_ERROR"* ]]; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="PRECHECK_ERROR"
        reason="${precheck_reason:-Server Filter 判定为 UNKNOWN/PRECHECK_ERROR}"
        log "Server Filter：UNKNOWN/PRECHECK_ERROR"
        log "原因：$reason"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        return 0
    fi

    # 不在这里使用 sshd -Q 判定服务端能力。CentOS 6/OpenSSH 5.3 的 -Q
    # 不提供现代版本的算法查询；最终能力以本次测试配置的 sshd -t + sshd -T
    # 和真实 SSH 协商为准。

    # CentOS 6 的 DSA 测试只有真正存在 DSA host key 时才执行。
    if [[ "$hostkey" == "ssh-dss" && ! -f /etc/ssh/ssh_host_dsa_key ]]; then
        NR="FAIL"
        AR="NOT_TESTED"
        CR="NEGOTIATION_FAIL"
        reason="缺少 /etc/ssh/ssh_host_dsa_key，服务器无法形成本测试 HostKey 组合"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        log "NEGOTIATION_FAIL [#$idx] $desc — $reason"
        return 0
    fi

    # CentOS 6 SSH-1 使用原脚本的 Protocol 1 配置；SSH-2 使用统一配置。
    if [[ "$proto" == "1" ]]; then
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        if ! make_ssh1_config "$idx" "$desc" "$cipher" "$tmp" "$compression"; then
            rm -f "$tmp"
            NR="FAIL"; AR="NOT_TESTED"; CR="NEGOTIATION_FAIL"
            reason="生成 SSH-1 测试配置失败，组合无法进入真实协商"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "" "" "" "" "$NR" "$AR" "$CR" "$reason"
            # 结果记为 FAIL（未进入真实协商），日志用词须与记录口径一致，
            # 避免出现"日志写 SKIP、计数却算 FAIL"的误导。
            log "NEGOTIATION_FAIL [#$idx] $desc — $reason"
            return 0
        fi
    else
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        if ! make_ssh2_config "$idx" "$desc" "$kex" "$cipher" "$mac" "$hostkey" "$tmp" "$compression"; then
            rm -f "$tmp"
            NR="FAIL"; AR="NOT_TESTED"; CR="NEGOTIATION_FAIL"
            reason="生成 SSH-2 测试配置失败，组合无法进入真实协商"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "" "" "" "" "$NR" "$AR" "$CR" "$reason"
            log "NEGOTIATION_FAIL [#$idx] $desc — $reason"
            return 0
        fi
    fi
    chmod 600 "$tmp"

    local syntax_err
    syntax_err="$(mktemp "${TMP_DIR}/algo_sshd_t.XXXXXX")"

    if ! "$SSHD_BIN" -t -f "$tmp" >"$syntax_err" 2>&1; then
        reason="$(head -3 "$syntax_err" | tr '\n' ' ')"
        rm -f "$syntax_err" "$tmp"

        NR="FAIL"
        AR="NOT_TESTED"
        CR="NEGOTIATION_FAIL"

        log "实际协商：UNKNOWN"
        log "总体结果：NEGOTIATION_FAIL"
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
        NR="FAIL"
        AR="NOT_TESTED"
        CR="NEGOTIATION_FAIL"
        reason="sshd -T -f 临时配置失败"
        log "实际协商：UNKNOWN"
        log "总体结果：NEGOTIATION_FAIL"
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
        algo_effective_supported compression "$compression" ||
            effective_unsupported+=" COMPRESSION[$compression]"
        if [[ -n "$effective_unsupported" ]]; then
            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="sshd -T 最终配置未启用:$effective_unsupported"
            log "实际协商：UNKNOWN"
            log "总体结果：NEGOTIATION_FAIL"
            log "原因：$reason"
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
            rm -f "$tmp"
            restore_after_test "算法不在临时配置有效集合" true
            return 0
        fi
    fi

    if ! mv -f "$tmp" "$SSHD_CONFIG"; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="CONFIG_INSTALL_FAILED"
        reason="测试配置安装失败（mv 失败），已停止本 TEST_CASE"
        log "总体结果：UNKNOWN"
        log "原因：$reason"
        rm -f "$tmp"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        restore_after_test "测试配置安装失败"
        return 0
    fi

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
        NR="FAIL"
        AR="NOT_TESTED"
        CR="NEGOTIATION_FAIL"
        reason="sshd 重启后无法读取最终生效配置，测试组合无法可靠进入协商：sshd -T -f $SSHD_CONFIG"
        log "实际协商：UNKNOWN"
        log "总体结果：NEGOTIATION_FAIL"
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
        algo_effective_supported compression "$compression" ||
            running_unsupported+=" COMPRESSION[$compression]"
        if [[ -n "$running_unsupported" ]]; then
            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="重启后 sshd -T 有效配置与测试项不一致，组合未真正生效:$running_unsupported"
            log "实际协商：UNKNOWN"
            log "总体结果：NEGOTIATION_FAIL"
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

    client_out="$(mktemp "${TMP_DIR}/algo_client.XXXXXX")"

    if $AUTO; then
        env_log "自动认证：root@127.0.0.1，临时公钥 marker=${AUTO_MARKER}"
        # 后台启动客户端并登记 PID：一旦脚本被 INT/TERM 打断，restore_all 可
        # 据 CLIENT_PID 终止该客户端，避免残留进程占用 sshd 连接导致恢复受阻。
        if [[ "$proto" == "1" ]]; then
            run_auto_ssh1 "$cipher" "$client_out" "$compression" &
        else
            run_auto_ssh2 "$kex" "$cipher" "$mac" "$hostkey" "$client_out" "$compression" &
        fi
        CLIENT_PID=$!
        # 先捕获退出码，再立刻清空 CLIENT_PID：wait 返回后子进程已被回收，
        # 若此时才收到 INT/TERM，restore_all 不会再对可能被系统复用的旧 PID
        # 误发 kill。rc 必须在 wait 之后的第一时间取值，故排在清空之前。
        wait "$CLIENT_PID"
        rc=$?
        CLIENT_PID=""
    else
        log "手动模式：等待外部客户端（如 CF Worker）发起连接本项。"
        server_delta="$(wait_for_manual_client "$server_log" "$log_before")"
        rc=0
    fi

    if [[ -n "$server_log" ]] && $AUTO; then
        server_delta="$(wait_for_server_log "$server_log" "$log_before")"
    fi

    # --------------------------------------------------------
    # 先解析服务端日志（server_delta）得到实际协商参数。
    #
    # 为何两种模式都要做：OpenSSH 5.x（CentOS 6 的 5.3）客户端日志完全不含
    # "kex: algorithm:"/"kex: host key algorithm:"，只有服务端 DEBUG3 会输出
    # "list_hostkey_types: <algo>" 和旧式 "kex: server->client <cipher> <mac> <comp>"。
    # 此前该解析块被误限定为「仅手动模式（! $AUTO）」，导致自动模式下 5.x
    # 的 NH（HostKey）恒为 UNKNOWN，进而把每一项都判成 NEGOTIATION_MISMATCH。
    # 现代客户端（>=6.5）能提供更新更全的值，下面客户端解析块会按「非空才覆盖
    # / 空才回填」的规则择优补全，因此这里是安全的。
    # --------------------------------------------------------
    if [[ "$proto" == "2" ]]; then
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
        # OpenSSH 5.x（CentOS 6 的 5.3）既不输出 "kex: algorithm:" 也不输出
        # 上述 "kex: <algo>" 形式；KEX 只能在 KEXINIT 转储里看到。当服务端
        # 用 KexAlgorithms 锁定了 KEX 时，服务端 KEXINIT 的 KEX 行只含**单个**
        # 算法（如 "kex_parse_kexinit: diffie-hellman-group14-sha1"）；
        # 客户端那条则是完整逗号列表。故取"无逗号的 diffie/ecdh/curve/gss 单值"
        # 作为 5.x 的实际协商 KEX 兜底。若本身没锁（多值列表）则匹配不到，
        # NK 仍为空，交由后续"KEX 断言"逻辑处理，不会误判。
        if [[ -z "$NK" ]]; then
            NK="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex_parse_kexinit: (diffie-hellman|ecdh|curve25519|curve448|gss)-[^,[:space:]]+[[:space:]]*$' |
                sed -E 's/.*kex_parse_kexinit:[[:space:]]*//' | awk '{print $1}' | tr -d '\r')"
        fi
        # 旧式 "kex: server->client <cipher> <mac> <comp>"。注意真实 syslog
        # （如 /var/log/secure，经 rsyslog）会在行首加 "时间戳 主机名 进程[pid]:" 前缀，
        # 使绝对列号（$4/$5）错位（取到 "debug1:"/"kex:"）。故改为以
        # "server->client " 为锚点取其后第 1、2 个字段，前缀无关。
        if [[ -z "$NC" ]]; then
            NC="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: server->client ' |
                sed -n 's/.*kex: server->client \([^ ]*\).*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NM" ]]; then
            NM="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: server->client ' |
                sed -n 's/.*kex: server->client [^ ]* \([^ ]*\).*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(extract_negotiated_hostkey "$server_delta")"
        fi
    fi

    # --------------------------------------------------------
    # 自动模式：优先从 ssh -vvv 得到实际协商参数。
    # 这比用 ssh 退出码判断算法结果准确。
    # --------------------------------------------------------
    if [[ "$proto" == "2" && -s "$client_out" ]]; then
        # 注意：现代格式的提取结果若非空才覆盖，否则会清空服务端日志路径
        # （server_delta）已解析出的值——OpenSSH 5.x 客户端根本不输出
        # "kex: algorithm:"/"kex: host key algorithm:"，"$()" 会得到空串并覆盖。
        local _nk _nh _nc _nm
        _nk="$(grep -m1 -E 'kex: algorithm: ' "$client_out" |
            sed 's/.*kex: algorithm: //' | tr -d '\r')"
        [[ -n "$_nk" ]] && NK="$_nk"
        _nh="$(grep -m1 -E 'kex: host key algorithm: ' "$client_out" |
            sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        [[ -n "$_nh" ]] && NH="$_nh"
        # 同样遵循「非空才覆盖」：5.x 客户端无 "server->client cipher:"/"MAC:"
        # 字段，若不加守卫会用空串清掉上面从服务端日志解析出的真实值。
        _nc="$(grep -m1 -E 'server->client cipher: ' "$client_out" |
            sed -n 's/.*server->client cipher: \([^ ]*\).*/\1/p' | tr -d '\r')"
        [[ -n "$_nc" ]] && NC="$_nc"
        # 现代 OpenSSH（>=6.5）日志形如：
        #   kex: server->client cipher: aes256-ctr MAC: hmac-sha2-256-etm@openssh.com compression: none
        # MAC 出现在同一行的 "MAC: " 之后，而不是 "server->client MAC: "，
        # 且 MAC 与 compression 之间只有一个空格。注意贪婪的 .* 会一路吃到
        # 最后一个 "MAC: "，故用行尾锚定取出真正的 MAC 字段。
        _nm="$(grep -m1 -E 'kex: server->client .*MAC: ' "$client_out" |
            sed -n 's/.* MAC: \([^ ]*\).*/\1/p' | tr -d '\r')"
        [[ -n "$_nm" ]] && NM="$_nm"

        # OpenSSH 5.x 使用旧式日志格式，例如：
        #   kex: server->client aes256-ctr hmac-sha1 none
        #   kex: client->server aes256-ctr hmac-sha1 none
        # 旧版本没有现代的 “cipher:/MAC:” 字段。
        #
        # 关键：旧式按位置切分的回退只能用于真正的旧格式日志。若当前行已是
        # 现代格式（含 "cipher:" 关键字），按空格位置取第 N 列会把
        # "cipher:"、"aes256-ctr" 当成 MAC，造成"实际 MAC = 密文算法"这类
        # 假协商值，进而误判 NEGOTIATION_MISMATCH。故先判定日志是新还是旧。
        local legacy_kex=false
        if ! grep -qE 'kex: server->client cipher: ' "$client_out"; then
            legacy_kex=true
        fi
        if [[ -z "$NK" ]]; then
            NK="$(grep -m1 -E 'kex: (diffie-|ecdh-|curve|gss-).*' "$client_out" |
                sed -E 's/.*kex: (.*)/\1/' | awk '{print $1}' | tr -d '\r')"
        fi
        if [[ -z "$NC" && "$legacy_kex" == true ]]; then
            NC="$(grep -m1 -E 'kex: server->client ' "$client_out" |
                sed -n 's/.*server->client \([^ ]*\) .*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NM" && "$legacy_kex" == true ]]; then
            NM="$(grep -m1 -E 'kex: server->client ' "$client_out" |
                sed -n 's/.*server->client [^ ]* \([^ ]*\) .*/\1/p' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(extract_negotiated_hostkey "$(cat "$client_out")")"
        fi
    fi

    # 压缩协商结果（仅压缩测试项需要）
    local NCOMP=""
    if [[ -n "$compression" && -s "$client_out" ]]; then
        NCOMP="$(extract_negotiated_compression "$(cat "$client_out")")"
    fi
    if [[ -n "$compression" && -z "$NCOMP" && "$AUTO" == false ]]; then
        # 手动模式没有客户端 DEBUG3；服务端 delta 是实际 Compression 的唯一
        # 协商证据，必须在 NR 判断前解析。
        NCOMP="$(extract_negotiated_compression "$server_delta")"
    fi
    [[ -n "$compression" ]] && RESULT_COMPRESSION_ACTUAL="${NCOMP:-UNKNOWN}"

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
        # 客户端与真实协商的权威证据判定：本轮客户端 -vvv 是否真正完成了一次
        # KEX（出现 "kex: algorithm:"/"host key algorithm:"）。若完成，则服务端
        # 日志里的 "kex_exchange_identification: Connection closed by remote host"
        # 极可能来自脚本自身的行为——sshd_port_listening / wait_service_ready 会
        # 用 /dev/tcp 探测端口，探测连接一建立即关闭，sshd 必然把这类"客户端未
        # 发 banner 就断开"记为 kex_exchange_identification。systemd 环境下
        # detect_log_file 走 JOURNAL:，read_log_delta 的 --since 只有秒级精度，
        # 会把同秒内这些探测噪声一并读入 server_delta，从而把一次成功的协商
        # 误判为 NEGOTIATION_FAIL。此处以客户端日志为准：客户端证据表明协商
        # 成功时不因服务端单方面的探测噪声而翻案。
        local client_negotiated=false
        if [[ "$proto" == "2" && -s "$client_out" ]] &&
            grep -qE 'kex: algorithm: ' "$client_out" 2>/dev/null &&
            grep -qE 'kex: host key algorithm: ' "$client_out" 2>/dev/null; then
            client_negotiated=true
        fi
        # 服务端日志命中协商失败模式时，若客户端已明确完成协商则忽略服务端
        # 的单方面噪声；否则按失败处理。
        local server_neg_fail=false
        if ! $client_negotiated && text_matches "$negotiation_pattern" "$server_delta"; then
            server_neg_fail=true
        fi
        if $server_neg_fail || \
           grep -qiE "$negotiation_pattern" "$client_out" 2>/dev/null; then

            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="$(last_matching_text "$negotiation_pattern" "$server_delta")"
            [[ -n "$reason" ]] || reason="$(grep -hiE "$negotiation_pattern" "$client_out" 2>/dev/null | tail -1)"

        # 本分支比对的是 SSH-2 的 KEX/Cipher/MAC/HostKey/Compression 五元组，
        # 且依据 NK/NC/NM/NH 这些 SSH-2 专有解析变量。SSH-1(proto=1) 下这些
        # 变量取不到值（NK/NM 为 "N/A"、NH 为 "UNKNOWN"），旧代码因 "N/A" 非空
        # 会误入本分支，并写入 SSH-2 专用文案 —— 造成 SSH-1 结果被污染。
        # 故显式加 proto == "2" 守卫；SSH-1 的判定完全交给上方 SSH-1 专用分支。
        elif [[ "$proto" == "2" ]] && \
         { { [[ "$cipher" == chacha20-poly1305@openssh.com || "$cipher" == aes128-gcm@openssh.com || "$cipher" == aes256-gcm@openssh.com ]] && [[ -n "$NK$NC$NH" ]]; } || \
           [[ -n "$NK$NC$NM$NH" ]]; }; then
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
            # KEX 断言：仅在本机能写 KexAlgorithms（即 sshd 支持该指令）时成立。
            # CentOS 6 的 5.3p1 回溯支持 KexAlgorithms，故此处会真正做断言；
            # 而真正的旧 5.x 上游版不支持该指令（sshd_supports_kex_algorithms 返回假），
            # 此时 KEX 由编译期顺序决定，跳过断言以免误判。
            #
            # 关键防误判：若因日志形态导致 NK 仍未解析到（空串），不能当成
            # "协商结果与固定值不一致"——那是"没取到证据"，不是"协商失败"。
            # 此时只跳过 KEX 断言（视为未知），仍继续校验可解析的 cipher/MAC/hostkey。
            local kex_matches=true
            if sshd_supports_kex_algorithms && [[ -n "$NK" ]]; then
                [[ "$NK" == "$kex" ]] || kex_matches=false
            fi
            # 同理：HostKey 若未解析到（空串）也不能当作"与固定值不一致"。
            # CentOS 6 的 HostKey 由 HostKey 私钥文件间接锁定，服务端日志的
            # "list_hostkey_types: <algo>" 是可靠证据；只有当该证据确实取到时
            # 才做相等断言，取不到则跳过（视为未知），避免把"没取到"误判成"不匹配"。
            local hostkey_matches=true
            if [[ -n "$NH" ]]; then
                [[ "$NH" == "$hostkey" ]] || hostkey_matches=false
            fi
            if [[ "$kex_matches" == true && "$NC" == "$cipher" && "$mac_matches" == true && "$hostkey_matches" == true ]]; then
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

    # SSH-1 实际协商参数从旧版 OpenSSH debug 输出中尽量提取。
    if [[ "$proto" == "1" && -s "$client_out" ]]; then
        # 注意：不能宽泛匹配 "cipher "，否则会把错误提示行
        # "Selected cipher type des not supported by server." 里的 "type"
        # 误当成实际 cipher。这里要求匹配真实协商行
        # （debug1: ... cipher: X / Using encryption algorithm X），并显式排除
        # 含 "not supported"/"Unknown cipher" 的失败行。
        NC="$(grep -m1 -E 'Using encryption algorithm|cipher: |[Rr]eading cipher|encryption algorithm' "$client_out" 2>/dev/null | \
            grep -viE 'not supported|unknown cipher|bad cipher|no matching' | \
            sed -E 's/.*(Using encryption algorithm|cipher:|encryption algorithm)[[:space:]]+//' | awk '{print $1}' | tr -d '\r')"
        [[ -z "$NC" ]] && NC="$(grep -m1 -E 'ssh_dss|SSH1.*cipher|encrypt.*(3des|blowfish|idea|arcfour|des)' "$client_out" 2>/dev/null | \
            grep -viE 'not supported|unknown cipher|bad cipher' | \
            grep -oiE '(3des|blowfish|idea|arcfour|des)(-cbc)?' | head -1 | tr -d '\r')"
    fi

    # SSH-1 的服务端日志是主要判断依据；现代 SSH 客户端可能自身已移除 SSH-1。
    if [[ "$proto" == "1" ]]; then
        # 服务端不支持该 SSH-1 cipher 是"期望的负结果"，不是脚本/环境缺陷。
        # OpenSSH 5.3p1（CentOS 6）没有 Cipher 配置项，SSH-1 cipher 集合完全由
        # 编译期决定（例如内建无 DES/IDEA），无法用 sshd -t 预检，只能靠真实
        # 握手暴露。客户端会明确报 "Selected cipher type X not supported by
        # server"（服务端不具备该 cipher）或 "Unknown cipher type 'X'"（客户端
        # 自身不具备）。两者都应按 SERVER-FILTER/UNSUPPORTED 归类，避免被
        # 记成令人误解的协商失败。
        local ssh1_unsupported=""
        ssh1_unsupported="$(grep -m1 -oiE 'Selected cipher type [^ ]+ not supported by server|Unknown cipher type[^\r]*' "$client_out" 2>/dev/null | tr -d '\r')"

        # ----------------------------------------------------------------
        # 服务端权威 cipher（重要）：
        #   SSH-1 没有算法协商报文，客户端日志的 "cipher: <x>" 只是"请求值"，
        #   并非最终落地值。唯一权威来源是服务端 DEBUG1 行
        #       debug1: Encryption type: <cipher>
        #   典型陷阱：客户端 `-1 -c arcfour` 时 OpenSSH 5.3p1 会打印
        #       "No valid SSH1 cipher, using 3des instead."
        #   随后实际用 3des 完成握手，客户端日志里却仍残留 arcfour 字样。
        #   若只看客户端日志，会把 arcfour 记成 PASS（假 PASS），而真实
        #   落地的是 3des。此处改用服务端值判定，并识别"降级"。
        # ----------------------------------------------------------------
        local ssh1_server_cipher=""
        ssh1_server_cipher="$(printf '%s\n' "$server_delta" |
            grep -m1 -oiE 'Encryption type: [^ ,]+' 2>/dev/null |
            sed -E 's/.*Encryption type: //' | tr -d '\r')"
        # 客户端自报"已降级"的显式证据
        local ssh1_client_downgrade=""
        ssh1_client_downgrade="$(grep -m1 -oiE 'No valid SSH1 cipher, using [^ ]+ instead' "$client_out" 2>/dev/null | tr -d '\r')"

        if [[ -n "$ssh1_unsupported" ]]; then
            # 与 SSH-2 的 Server Filter 约定保持一致：NR=FAIL 但 CR 明确标注
            # SERVER_UNSUPPORTED，使这类"期望的负结果"在汇总与日志中可一眼区分，
            # 不会被误读为脚本/环境缺陷。
            NR="FAIL"
            AR="NOT_TESTED"
            CR="SERVER_UNSUPPORTED"
            reason="SSH-1 cipher 服务器/客户端不支持：$ssh1_unsupported"
        elif text_matches 'Unable to negotiate|no matching|Connection closed|Did not receive identification' "$server_delta" || \
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
            # 握手 + 认证都成功。此时若服务端给出了权威 cipher，就以它作为
            # 实际协商值；并检查是否发生了"请求值 ≠ 落地值"的降级。
            [[ -n "$ssh1_server_cipher" ]] && NC="$ssh1_server_cipher"
            local ssh1_want="$cipher"
            [[ "$ssh1_want" == *-cbc ]] && ssh1_want="${ssh1_want%-cbc}"
            if [[ -n "$ssh1_server_cipher" && -n "$ssh1_want" &&
                  "${ssh1_server_cipher,,}" != "${ssh1_want,,}" ]]; then
                # 期望 cipher 与实际落地不一致 → 降级。这不是"通过"，而是
                # 需要人工关注的偏差（例如 arcfour 实际落到 3des）。
                NR="WARN"
                AR="PASS"
                CR="NEGOTIATION_MISMATCH"
                reason="SSH-1 实际使用 cipher 与请求不一致（降级）：请求 ${cipher}，服务端实际 ${ssh1_server_cipher}${ssh1_client_downgrade:+（客户端报：$ssh1_client_downgrade）}"
            elif [[ -n "$ssh1_client_downgrade" ]]; then
                # 服务端日志未取到，但客户端明确报了降级
                NR="WARN"
                AR="PASS"
                CR="NEGOTIATION_MISMATCH"
                reason="SSH-1 客户端已降级：$ssh1_client_downgrade（服务端日志未捕获到 Encryption type 行）"
            else
                NR="PASS"
                AR="PASS"
                CR="PASS"
                NH="RSA1"
                # 清空 reason：上方为 SSH-2 设计的算法匹配断言在 SSH-1 下会
                # 走 elif 分支并写入 "客户端 DEBUG3 检测到的实际协商算法与
                # 本次固定测试组合不一致" 这类不适用于 SSH-1 的文案（SSH-1
                # 无算法协商报文，该断言无意义）。此处既然已判定 PASS，必须
                # 显式清空，避免该旧文案残留到结果报告中造成误解。
                reason=""
            fi
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
        if [[ -n "$compression" && -z "$NCOMP" ]]; then
            NCOMP="$(extract_negotiated_compression "$server_delta")"
        fi
    fi
    [[ -n "$compression" ]] && RESULT_COMPRESSION_ACTUAL="${NCOMP:-UNKNOWN}"

    # 四个结果维度独立记录：ssh 进程退出码只决定客户端进程，不能替代
    # 协商、认证或远端命令执行证据。
    if $AUTO; then
        if [[ "$rc" -eq 0 ]]; then
            RESULT_CLIENT_PROCESS="PASS"
        else
            RESULT_CLIENT_PROCESS="FAIL"
        fi
    else
        RESULT_CLIENT_PROCESS="NOT_RUN"
    fi
    if [[ "$NR" == "PASS" && "$AR" == "PASS" ]]; then
        if grep -qiE 'Exit status 0|exit status 0|Sending command: true|request succeeded' "$client_out" 2>/dev/null; then
            RESULT_COMMAND="PASS"
        elif grep -qiE 'Exit status [1-9]|command failed|request failed' "$client_out" 2>/dev/null; then
            RESULT_COMMAND="FAIL"
        else
            # 协商、认证均成功，但日志中既无远端命令成功也无失败证据
            # （自动/手动模式同理），只能记 UNKNOWN，不臆测。
            RESULT_COMMAND="UNKNOWN"
        fi
    else
        # 未同时满足协商+认证成功：无法断言远端命令执行结果，记 NOT_RUN。
        RESULT_COMMAND="NOT_RUN"
    fi

    if [[ "$NR" == "PASS" && "$AR" == "UNKNOWN" && -z "$reason" ]]; then
        reason="协商成功；认证状态无法从当前日志准确确定"
    fi

    if [[ "$proto" == "1" ]]; then
        log "实际协商：SSH-1 CIPHER=${NC:-UNKNOWN} SERVER_KEY=${NH:-ssh-rsa1/UNKNOWN}"
    else
        log "实际协商：KEX=${NK:-UNKNOWN} CIPHER=${NC:-UNKNOWN} MAC=${NM:-UNKNOWN} HOST_KEY=${NH:-UNKNOWN}"
    fi
    # 合并协商/认证/命令/客户端四个维度为一行总体结果。统一走 compute_overall，
    # 与 record_result/write_result 共用同一判定口径，避免日志与计数漂移。
    local overall_txt
    overall_txt="$(compute_overall "$NR" "$AR" \
        "${RESULT_COMMAND:-UNKNOWN}" "${RESULT_CLIENT_PROCESS:-UNKNOWN}")"
    log "总体结果：${overall_txt}"
    log "客户端结果：${CR}"
    [[ -n "$reason" ]] && log "原因：${reason}"

    # Compression Coverage 只接受实际协商证据；固定测试值不能替代缺失的
    # 协商日志，且 mark_actual_coverage 还会要求 NR=PASS。
    local actual_coverage_compression="${RESULT_COMPRESSION_ACTUAL:-UNKNOWN}"
    mark_actual_coverage "$proto" "$NK" "$NC" "$NM" "$NH" \
        "$actual_coverage_compression" "$NR"

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
log "服务器过滤保留 TEST_CASE：$SERVER_FILTERED_TESTS 项（UNSUPPORTED=$SERVER_UNSUPPORTED_TESTS，UNKNOWN/PRECHECK_ERROR=$SERVER_UNKNOWN_TESTS）"
log "============================================================"

env_log "配置备份: $BACKUP_FILE"
env_log "测试项总数: $TEST_INDEX"
env_log "版本过滤项数: $FILTERED_TESTS"
env_log "服务器过滤保留项数: $SERVER_FILTERED_TESTS（UNSUPPORTED=$SERVER_UNSUPPORTED_TESTS，UNKNOWN/PRECHECK_ERROR=$SERVER_UNKNOWN_TESTS）"
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


env_log "结束时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
env_log "PASS: $PASS"
env_log "FAIL: $FAIL"
env_log "WARN: $WARN"
env_log "UNKNOWN: $UNKNOWN"
env_log "SKIP: $SKIP"
env_log "配置恢复要求: 已注册 EXIT/INT/TERM cleanup"
[[ "$RECOVERY_SELFHEAL_UNAVAILABLE" == "true" ]] && \
    env_log "注意: 崩溃自愈不可用（缺 crontab 或安装失败），本次为无自愈模式运行"

log ""
log "============================================================"
log "测试完成"
log "PASS: $PASS"
log "FAIL: $FAIL"
log "WARN: $WARN"
log "UNKNOWN: $UNKNOWN"
log "SKIP: $SKIP"
log "总测试项: $TEST_INDEX"
log "计划 Coverage（仅用于生成器决策）: KEX=$(printf '%s\n' "${!PLAN_COVERAGE_SEEN[@]}" | sed -n 's/^kex|//p' | paste -sd, -) Cipher=$(printf '%s\n' "${!PLAN_COVERAGE_SEEN[@]}" | sed -n 's/^cipher|//p' | paste -sd, -) MAC=$(printf '%s\n' "${!PLAN_COVERAGE_SEEN[@]}" | sed -n 's/^mac|//p' | paste -sd, -) HostKey=$(printf '%s\n' "${!PLAN_COVERAGE_SEEN[@]}" | sed -n 's/^hostkey|//p' | paste -sd, -) Compression=$(printf '%s\n' "${!PLAN_COVERAGE_SEEN[@]}" | sed -n 's/^compression|//p' | paste -sd, -)"
log "SSH-2 实际 Coverage（仅成功协商结果）: KEX=$(printf '%s\n' "${!ACTUAL_SSH2_COVERAGE_SEEN[@]}" | sed -n 's/^kex|//p' | paste -sd, -) Cipher=$(printf '%s\n' "${!ACTUAL_SSH2_COVERAGE_SEEN[@]}" | sed -n 's/^cipher|//p' | paste -sd, -) MAC=$(printf '%s\n' "${!ACTUAL_SSH2_COVERAGE_SEEN[@]}" | sed -n 's/^mac|//p' | paste -sd, -) HostKey=$(printf '%s\n' "${!ACTUAL_SSH2_COVERAGE_SEEN[@]}" | sed -n 's/^hostkey|//p' | paste -sd, -) Compression=$(printf '%s\n' "${!ACTUAL_SSH2_COVERAGE_SEEN[@]}" | sed -n 's/^compression|//p' | paste -sd, -)"
log "SSH-1 实际 Coverage（仅成功协商结果）: Cipher=$(printf '%s\n' "${!ACTUAL_SSH1_COVERAGE_SEEN[@]}" | sed -n 's/^cipher|//p' | paste -sd, -) Compression=$(printf '%s\n' "${!ACTUAL_SSH1_COVERAGE_SEEN[@]}" | sed -n 's/^compression|//p' | paste -sd, -)"


log "结果与详细日志：$LOG_FILE"
log "============================================================"

exit 0
