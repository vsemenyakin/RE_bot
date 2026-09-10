# Общая логика SSH к живой Raspberry Pi -- подключается обёртками pi-exec/push/pull.
# Креды берутся из окружения (их пробрасывает subscription-ветка при docker run):
#   RE_PI_HOST (обяз.), RE_PI_USER (по умолч. pi), RE_PI_PORT (22),
#   RE_PI_PASSWORD ИЛИ RE_PI_KEY, RE_PI_WORKDIR (/tmp/re-agent).
#
# Осторожно: пароль/ключ Pi доступны внутри контейнера. Это приемлемо только для
# ДОВЕРЕННОГО образца (свой бинарь) -- недоверенный код мог бы их прочитать.

_pi_check() {
    if [ -z "${RE_PI_HOST:-}" ]; then
        echo "живая Pi не подключена (RE_PI_HOST не задан) -- используй rpi-run (qemu)" >&2
        return 1
    fi
}

_pi_user() { echo "${RE_PI_USER:-pi}"; }
_pi_wd()   { echo "${RE_PI_WORKDIR:-/tmp/re-agent}"; }

# Опции ssh/scp: accept-new -- принять ключ нового хоста один раз (как в agent.py),
# затем сверять; без блокирующих запросов.
_pi_opts() {
    echo "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=no -p ${RE_PI_PORT:-22}"
}

# Выполнить ssh/scp с нужным способом аутентификации (ключ приоритетнее пароля).
_pi_ssh() {   # $@ = аргументы ssh после опций
    local opts; opts=$(_pi_opts)
    if [ -n "${RE_PI_KEY:-}" ]; then
        ssh $opts -i "$RE_PI_KEY" "$@"
    elif [ -n "${RE_PI_PASSWORD:-}" ]; then
        SSHPASS="$RE_PI_PASSWORD" sshpass -e ssh $opts "$@"
    else
        ssh $opts "$@"
    fi
}

_pi_scp() {   # $@ = аргументы scp после опций (scp использует -P, не -p, для порта)
    local opts; opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -P ${RE_PI_PORT:-22}"
    if [ -n "${RE_PI_KEY:-}" ]; then
        scp $opts -i "$RE_PI_KEY" "$@"
    elif [ -n "${RE_PI_PASSWORD:-}" ]; then
        SSHPASS="$RE_PI_PASSWORD" sshpass -e scp $opts "$@"
    else
        scp $opts "$@"
    fi
}
