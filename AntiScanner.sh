#!/bin/bash

# Стили и цвета
BOLD='\033[1m'
B_CYAN='\033[1;36m'
B_GREEN='\033[1;32m'
B_YELLOW='\033[1;33m'
B_RED='\033[1;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${B_RED}Ошибка: Запустите от имени root.${NC}"
    exit 1
fi

S="/usr/local/bin/update-antiscanner.sh"
STATE_DIR="/etc/antiscanner"
BACKUP_DIR="$STATE_DIR/backup/$(date +%Y%m%d-%H%M%S)"
LIST_URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
SET4="antiscanner_v4"
SET6="antiscanner_v6"

echo -e "${B_CYAN}Конфигурация AntiScanner (ipset)${NC}"

# ------------------------------------------------------------
# Определяем, есть ли предыдущая установка и какой у неё режим
# ------------------------------------------------------------
PREV_MODE=""
LEGACY=0
if [ -f "$S" ]; then
    PREV_MODE=$(sed -n 's/^MODE="\([a-z]*\)".*/\1/p' "$S" | head -n1)
    if ! grep -q "ipset" "$S"; then
        LEGACY=1
    fi
fi

if [ "$LEGACY" -eq 1 ]; then
    echo -e "${B_YELLOW}Найдена старая установка без ipset (режим: ${PREV_MODE:-неизвестен}). Выполню миграцию.${NC}"
elif [ -n "$PREV_MODE" ]; then
    echo -e "${B_YELLOW}Найдена установка на ipset (режим: $PREV_MODE). Будет обновление.${NC}"
fi

echo -e "Выберите метод защиты:"
echo -e "1) UFW (рекомендуется для Ubuntu/Debian)"
echo -e "2) iptables (прямые правила)"
if [ -n "$PREV_MODE" ]; then
    read -r -p "Ваш выбор [1-2, Enter = оставить $PREV_MODE]: " FW_CHOICE
    if [ -z "$FW_CHOICE" ]; then
        [ "$PREV_MODE" = "ufw" ] && FW_CHOICE=1 || FW_CHOICE=2
    fi
else
    read -r -p "Ваш выбор [1-2]: " FW_CHOICE
fi

case $FW_CHOICE in
    1) MODE="ufw" ;;
    2) MODE="iptables" ;;
    *) echo "Неверный выбор. Выход."; exit 1 ;;
esac

# ------------------------------------------------------------
# Установка пакетов
# ------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive

if [ "$MODE" = "ufw" ]; then
    if ! command -v ufw >/dev/null; then
        echo -e "${B_YELLOW}Установка UFW...${NC}"
        apt-get update -qq && apt-get install -y ufw -qq
    fi

    # iptables-persistent перезаписывал бы правила UFW
    if dpkg -l | grep -q iptables-persistent; then
        echo -e "${B_YELLOW}Удаление конфликтующего iptables-persistent...${NC}"
        apt-get purge -y iptables-persistent -qq
    fi
else
    echo -e "${B_YELLOW}Настройка компонентов iptables...${NC}"
    mkdir -p /etc/iptables
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    apt-get update -qq && apt-get install -y iptables iptables-persistent -qq
fi

echo -e "${B_YELLOW}Установка ipset, curl, logrotate...${NC}"
apt-get update -qq && apt-get install -y ipset curl logrotate -qq
if ! command -v ipset >/dev/null; then
    echo -e "${B_RED}Не удалось установить ipset. Выход, старые правила не тронуты.${NC}"
    exit 1
fi

# ------------------------------------------------------------
# Резервные копии всего, что будем менять
# ------------------------------------------------------------
backup_file() {
    [ -e "$1" ] || return 0
    mkdir -p "$BACKUP_DIR"
    cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')"
}

mkdir -p "$STATE_DIR"
for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ufw/before.rules /etc/ufw/before6.rules \
         /etc/iptables/rules.v4 /etc/iptables/rules.v6 "$S"; do
    backup_file "$f"
done
if command -v iptables-save >/dev/null; then
    mkdir -p "$BACKUP_DIR"
    iptables-save > "$BACKUP_DIR/iptables-save.v4" 2>/dev/null
    ip6tables-save > "$BACKUP_DIR/ip6tables-save.v6" 2>/dev/null
fi
[ -d "$BACKUP_DIR" ] && echo -e "${B_YELLOW}Резервные копии на время миграции: $BACKUP_DIR (удалятся после успешной проверки)${NC}"

# ------------------------------------------------------------
# Ротация логов: храним только последние 7 дней
# ------------------------------------------------------------
cat << 'LOGROTATE_EOF' > /etc/logrotate.d/antiscanner
/var/log/antiscanner_update.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
}
LOGROTATE_EOF

# ------------------------------------------------------------
# Скрипт-обновлятор: ipset (атомарная подмена набора через swap)
# Подкоманды: (без аргументов) обновить список | restore | tcpflags
# ------------------------------------------------------------
cat << 'UPDATER_EOF' > "$S"
#!/bin/bash
MODE="__MODE__"
URL="__URL__"
STATE_DIR="/etc/antiscanner"
SAVE_FILE="$STATE_DIR/ipsets.save"
SET4="antiscanner_v4"
SET6="antiscanner_v6"
MAXELEM=262144
MIN_V4_ENTRIES=10

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

mkdir -p "$STATE_DIR"
exec 9>/run/antiscanner.lock
if ! flock -w 120 9; then
    log "[ERROR] Не удалось получить блокировку, другой экземпляр занят"
    exit 1
fi

create_sets() {
    ipset create -exist "$SET4" hash:net family inet  hashsize 4096 maxelem "$MAXELEM"
    ipset create -exist "$SET6" hash:net family inet6 hashsize 1024 maxelem "$MAXELEM"
}

restore_sets() {
    if [ -s "$SAVE_FILE" ]; then
        ipset restore -exist < "$SAVE_FILE" || log "[WARN] Не удалось полностью восстановить $SAVE_FILE"
    fi
}

save_sets() {
    { ipset save "$SET4"; ipset save "$SET6"; } > "$SAVE_FILE.tmp" && mv "$SAVE_FILE.tmp" "$SAVE_FILE"
}

# Атомарная загрузка: наполняем временный набор и меняем местами с рабочим
load_set() {
    local set="$1" fam="$2" hs="$3" file="$4" tmp="${1}_tmp" net
    ipset destroy "$tmp" 2>/dev/null
    ipset create "$tmp" hash:net family "$fam" hashsize "$hs" maxelem "$MAXELEM" || return 1
    if [ -s "$file" ]; then
        if ! sed "s/^/add $tmp /" "$file" | ipset restore -exist 2>/dev/null; then
            log "[WARN] Пакетная загрузка в $set не прошла, добавляю записи по одной"
            ipset flush "$tmp"
            while IFS= read -r net; do
                ipset add -exist "$tmp" "$net" 2>/dev/null || log "[WARN] Пропущена запись: $net"
            done < "$file"
        fi
    fi
    if ! ipset swap "$tmp" "$set"; then
        ipset destroy "$tmp" 2>/dev/null
        return 1
    fi
    ipset destroy "$tmp"
}

ensure_iptables_rules() {
    local cmd set
    for cmd in iptables ip6tables; do
        [ "$cmd" = "iptables" ] && set="$SET4" || set="$SET6"
        $cmd -N SCANNERS-BLOCK 2>/dev/null
        # Сбрасываем цепочку: заодно убираем тысячи старых правил по одному адресу
        $cmd -F SCANNERS-BLOCK
        $cmd -A SCANNERS-BLOCK -m set --match-set "$set" src -j DROP
        $cmd -C INPUT -j SCANNERS-BLOCK &>/dev/null || $cmd -I INPUT 1 -j SCANNERS-BLOCK
    done
}

setup_tcp_flags_protection() {
    local cmd rule
    local -a RULES=(
        "--tcp-flags ALL NONE"
        "--tcp-flags ALL ALL"
        "--tcp-flags ALL FIN,URG,PSH"
        "--tcp-flags ALL SYN,RST,ACK,FIN,URG"
        "--tcp-flags SYN,RST SYN,RST"
        "--tcp-flags SYN,FIN SYN,FIN"
        "! --syn -m conntrack --ctstate NEW"
    )
    for cmd in iptables ip6tables; do
        $cmd -L TCP-FLAGS-PROTECT -n &>/dev/null || $cmd -N TCP-FLAGS-PROTECT
        for rule in "${RULES[@]}"; do
            # shellcheck disable=SC2086
            $cmd -C TCP-FLAGS-PROTECT -p tcp $rule -j DROP 2>/dev/null || \
                $cmd -A TCP-FLAGS-PROTECT -p tcp $rule -j DROP
        done
        $cmd -C INPUT -p tcp -j TCP-FLAGS-PROTECT &>/dev/null || $cmd -I INPUT 1 -p tcp -j TCP-FLAGS-PROTECT
    done
}

case "${1:-update}" in
    restore)  create_sets; restore_sets; exit 0 ;;
    tcpflags) setup_tcp_flags_protection; exit 0 ;;
    update)   ;;
    *) echo "Использование: $0 [update|restore|tcpflags]"; exit 1 ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
RAW="$TMP_DIR/raw"; V4="$TMP_DIR/v4"; V6="$TMP_DIR/v6"
: > "$V4"; : > "$V6"

if ! curl -fsSL --max-time 30 "$URL" -o "$RAW" || [ ! -s "$RAW" ]; then
    log "[ERROR] Не удалось скачать список AntiScanner, оставляю текущие наборы без изменений"
    exit 1
fi

# Валидация: только корректные CIDR. Слишком широкие сети (v4 шире /8, v6 шире /16)
# отбрасываем, чтобы испорченный список не заблокировал весь интернет и вас самих.
awk -v f4="$V4" -v f6="$V6" '
{
    gsub(/\r/, ""); sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "")
    if ($0 == "" || $0 ~ /^#/) next
    s = $0; p = ""
    i = index(s, "/")
    if (i) {
        p = substr(s, i + 1); s = substr(s, 1, i - 1)
        if (p !~ /^[0-9]+$/) next
    }
    if (s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        n = split(s, a, ".")
        for (k = 1; k <= n; k++) if (a[k] + 0 > 255) next
        if (p == "") p = 32
        if (p + 0 < 8 || p + 0 > 32) next
        print s "/" p >> f4
    } else if (s ~ /^[0-9a-fA-F:]+$/ && s ~ /:.*:/) {
        if (p == "") p = 128
        if (p + 0 < 16 || p + 0 > 128) next
        print s "/" p >> f6
    }
}' "$RAW"

N4=$(wc -l < "$V4")
N6=$(wc -l < "$V6")
if [ "$N4" -lt "$MIN_V4_ENTRIES" ]; then
    log "[ERROR] В списке всего $N4 IPv4-записей (минимум $MIN_V4_ENTRIES), похоже на повреждённый файл. Наборы не изменены"
    exit 1
fi

create_sets
if ! load_set "$SET4" inet 4096 "$V4" || ! load_set "$SET6" inet6 1024 "$V6"; then
    log "[ERROR] Не удалось загрузить наборы ipset"
    exit 1
fi
save_sets

if [ "$MODE" = "iptables" ]; then
    ensure_iptables_rules
    setup_tcp_flags_protection
fi
# В режиме ufw правила лежат в before.rules и ссылаются на наборы по имени,
# поэтому ufw reload после обновления списка не нужен.

log "[SUCCESS] Список AntiScanner обновлён: IPv4=$N4, IPv6=$N6 (режим $MODE, ipset)"
UPDATER_EOF

sed -i "s|__MODE__|$MODE|; s|__URL__|$LIST_URL|" "$S"
chmod +x "$S"

# ------------------------------------------------------------
# Служба, которая создаёт наборы до загрузки файрвола.
# Без неё правила с --match-set не загрузятся после ребута
# (iptables-restore падает целиком, если набора ещё нет).
# ------------------------------------------------------------
cat << EOF > /etc/systemd/system/antiscanner-ipset.service
[Unit]
Description=Create and restore AntiScanner ipsets before firewall
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target ufw.service netfilter-persistent.service iptables.service ip6tables.service
Wants=network-pre.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$S restore

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable antiscanner-ipset.service >/dev/null 2>&1

# ------------------------------------------------------------
# Первый запуск: создаём наборы и наполняем их.
# Старые правила пока не трогаем: если загрузка не удалась, защита остаётся.
# ------------------------------------------------------------
"$S" restore
echo -e "${B_YELLOW}Загрузка списка в ipset...${NC}"
if ! "$S"; then
    N=$(ipset list -t "$SET4" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')
    if [ "${N:-0}" -eq 0 ]; then
        echo -e "${B_RED}Набор $SET4 пуст, список не скачался. Старые правила оставлены без изменений.${NC}"
        echo -e "${B_YELLOW}Проверьте доступ к $LIST_URL и запустите установку снова.${NC}"
        exit 1
    fi
    echo -e "${B_YELLOW}Скачать новый список не вышло, продолжаю с сохранённым набором ($N записей).${NC}"
fi

# ------------------------------------------------------------
# Миграция: удаление старых правил по одному адресу
# ------------------------------------------------------------
remove_legacy_ufw_rules() {
    local plain="AntiScanner-Block" hex f before after
    hex=$(printf '%s' "$plain" | od -An -tx1 | tr -d ' \n')
    for f in /etc/ufw/user.rules /etc/ufw/user6.rules; do
        [ -f "$f" ] || continue
        before=$(grep -c '^### tuple ###' "$f")
        # В user.rules комментарий хранится в hex-виде, поэтому старый sed по тексту его не находил.
        # Удаляем целиком блоки (строка tuple + правила до пустой строки).
        awk -v plain="$plain" -v hex="$hex" '
            /^### tuple ###/ { skip = (index(tolower($0), hex) || index($0, plain)) ? 1 : 0 }
            /^$/ { if (skip) { skip = 0; next } }
            { if (!skip) print }
        ' "$f" > "$f.new" && cat "$f.new" > "$f"
        rm -f "$f.new"
        after=$(grep -c '^### tuple ###' "$f")
        [ "$before" != "$after" ] && echo -e "${B_YELLOW}$f: удалено старых правил: $((before - after))${NC}"
    done
}

remove_legacy_iptables_chains() {
    local cmd
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null || continue
        while $cmd -D INPUT -j SCANNERS-BLOCK 2>/dev/null; do :; done
        $cmd -F SCANNERS-BLOCK 2>/dev/null && $cmd -X SCANNERS-BLOCK 2>/dev/null
    done
}

remove_tcp_chain_iptables() {
    local cmd
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null || continue
        while $cmd -D INPUT -p tcp -j TCP-FLAGS-PROTECT 2>/dev/null; do :; done
        $cmd -F TCP-FLAGS-PROTECT 2>/dev/null && $cmd -X TCP-FLAGS-PROTECT 2>/dev/null
    done
}

# ------------------------------------------------------------
# UFW: before.rules
# ------------------------------------------------------------
setup_tcp_flags_protection_ufw() {
    echo -e "${B_YELLOW}Установка защиты от аномальных TCP-флагов (UFW before.rules)...${NC}"
    local RULES_FILE CHAIN TMP_FILE
    for RULES_FILE in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [ -f "$RULES_FILE" ] || continue
        grep -q "AntiScanner-TCP-Flags" "$RULES_FILE" && continue

        if [[ "$RULES_FILE" == *before6.rules ]]; then
            CHAIN="ufw6-before-input"
        else
            CHAIN="ufw-before-input"
        fi

        TMP_FILE=$(mktemp)
        awk -v chain="$CHAIN" '
            /^COMMIT/ && !inserted {
                print "# --- AntiScanner-TCP-Flags: начало ---"
                print "-A " chain " -p tcp --tcp-flags ALL NONE -j DROP"
                print "-A " chain " -p tcp --tcp-flags ALL ALL -j DROP"
                print "-A " chain " -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP"
                print "-A " chain " -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP"
                print "-A " chain " -p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
                print "-A " chain " -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP"
                print "-A " chain " -p tcp ! --syn -m conntrack --ctstate NEW -j DROP"
                print "# --- AntiScanner-TCP-Flags: конец ---"
                inserted=1
            }
            { print }
        ' "$RULES_FILE" > "$TMP_FILE"
        # cat вместо mv: сохраняем права и владельца исходного файла
        cat "$TMP_FILE" > "$RULES_FILE"
        rm -f "$TMP_FILE"
    done
}

setup_ipset_block_ufw() {
    echo -e "${B_YELLOW}Подключение наборов ipset к UFW (before.rules)...${NC}"
    local f chain set tmp
    for f in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [ -f "$f" ] || continue
        if [[ "$f" == *before6.rules ]]; then
            chain="ufw6-before-input"; set="$SET6"
        else
            chain="ufw-before-input"; set="$SET4"
        fi

        # Убираем прошлую версию блока, чтобы повторный запуск не плодил дубли
        sed -i '/# --- AntiScanner-IPSet: begin ---/,/# --- AntiScanner-IPSet: end ---/d' "$f"

        tmp=$(mktemp)
        if grep -q '^# End required lines' "$f"; then
            # Ставим правило самым первым в цепочке, до разрешающих правил UFW
            awk -v chain="$chain" -v set="$set" '
                { print }
                /^# End required lines/ && !done {
                    print "# --- AntiScanner-IPSet: begin ---"
                    print "-A " chain " -m set --match-set " set " src -j DROP"
                    print "# --- AntiScanner-IPSet: end ---"
                    done = 1
                }
            ' "$f" > "$tmp"
        else
            echo -e "${B_YELLOW}В $f нет маркера '# End required lines', вставляю перед COMMIT (проверьте порядок правил).${NC}"
            awk -v chain="$chain" -v set="$set" '
                /^COMMIT/ && !done {
                    print "# --- AntiScanner-IPSet: begin ---"
                    print "-A " chain " -m set --match-set " set " src -j DROP"
                    print "# --- AntiScanner-IPSet: end ---"
                    done = 1
                }
                { print }
            ' "$f" > "$tmp"
        fi
        cat "$tmp" > "$f"
        rm -f "$tmp"
    done
}

restore_ufw_backups() {
    local f
    for f in user.rules user6.rules before.rules before6.rules; do
        [ -e "$BACKUP_DIR/_etc_ufw_$f" ] && cat "$BACKUP_DIR/_etc_ufw_$f" > "/etc/ufw/$f"
    done
}

ufw_is_active() {
    ufw status 2>/dev/null | grep -q "^Status: active"
}

if [ "$MODE" = "ufw" ]; then
    remove_legacy_ufw_rules
    setup_tcp_flags_protection_ufw
    setup_ipset_block_ufw

    if ufw_is_active; then
        if ! ufw reload; then
            echo -e "${B_RED}ufw reload не прошёл, возвращаю прежние файлы правил из $BACKUP_DIR${NC}"
            restore_ufw_backups
            ufw reload
            exit 1
        fi
    else
        echo -e "${B_RED}ВНИМАНИЕ: UFW сейчас не включён, правила применятся только после 'ufw enable'.${NC}"
        echo -e "${B_YELLOW}Сначала убедитесь, что разрешён SSH (ufw allow <порт>/tcp), иначе потеряете доступ.${NC}"
    fi

    # Прежние цепочки iptables больше не нужны: блокировку делает UFW
    remove_legacy_iptables_chains
    remove_tcp_chain_iptables

    systemctl enable ufw 2>/dev/null
    if systemctl is-enabled ufw &>/dev/null; then
        echo -e "${B_GREEN}UFW включён в автозагрузку, before.rules применится при ребуте.${NC}"
    else
        echo -e "${B_RED}ВНИМАНИЕ: ufw не в автозагрузке. Выполните: ufw enable${NC}"
    fi
else
    # Переход с UFW на iptables: убираем наши блоки из UFW
    remove_legacy_ufw_rules
    for f in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [ -f "$f" ] || continue
        sed -i '/# --- AntiScanner-IPSet: begin ---/,/# --- AntiScanner-IPSet: end ---/d' "$f"
        sed -i '/# --- AntiScanner-TCP-Flags: начало ---/,/# --- AntiScanner-TCP-Flags: конец ---/d' "$f"
    done
    command -v ufw >/dev/null && ufw_is_active && ufw reload

    # Цепочка SCANNERS-BLOCK уже пересоздана обновлятором с одним правилом на набор
    "$S" tcpflags
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    systemctl enable netfilter-persistent 2>/dev/null || systemctl enable iptables-persistent 2>/dev/null
    systemctl restart netfilter-persistent 2>/dev/null

    if systemctl is-enabled netfilter-persistent &>/dev/null; then
        echo -e "${B_GREEN}netfilter-persistent включён, правила переживут перезагрузку.${NC}"
    else
        echo -e "${B_RED}ВНИМАНИЕ: не удалось включить netfilter-persistent. После ребута правила iptables могут слететь!${NC}"
    fi
fi

# ------------------------------------------------------------
# Cron и служба обновления при старте
# ------------------------------------------------------------
C_JOB="20 3 * * * $S >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null | grep -v "$S" ; echo "$C_JOB") | crontab -

UPD_UNIT="/etc/systemd/system/antiscanner-update.service"
if [ -f "$UPD_UNIT" ]; then
    SYSTEMD_CHOICE="y"
    echo -e "${B_YELLOW}Найдена служба antiscanner-update, обновляю её файл (без устаревших зависимостей).${NC}"
else
    read -r -p $'\033[1;33mСоздать службу systemd для обновления при старте системы? [y/N]: \033[0m' SYSTEMD_CHOICE
fi
if [[ "$SYSTEMD_CHOICE" =~ ^[Yy]$ ]]; then
    cat << EOF > "$UPD_UNIT"
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network-online.target antiscanner-ipset.service
Wants=network-online.target
Requires=antiscanner-ipset.service

[Service]
Type=oneshot
ExecStart=$S
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable antiscanner-update.service
    echo -e "${B_YELLOW}Служба systemd создана и включена.${NC}"
fi

echo -e "${B_GREEN}AntiScanner успешно настроен через $MODE (ipset).${NC}"
echo -e "Проверка:"
echo -e "  ipset list -t $SET4 | grep 'Number of entries'"
if [ "$MODE" = "ufw" ]; then
    echo -e "  iptables -S ufw-before-input | grep match-set"
else
    echo -e "  iptables -S SCANNERS-BLOCK"
fi

# ------------------------------------------------------------
# Проверка результата. Бэкап удаляется только если всё реально работает,
# иначе он остаётся для ручного отката.
# ------------------------------------------------------------
verify_migration() {
    local n4
    n4=$(ipset list -t "$SET4" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')
    [ "${n4:-0}" -gt 0 ] || { echo "набор $SET4 пуст"; return 1; }
    ipset list -n 2>/dev/null | grep -qx "$SET6" || { echo "нет набора $SET6"; return 1; }
    if [ "$MODE" = "ufw" ]; then
        iptables -S ufw-before-input 2>/dev/null | grep -q "match-set $SET4" \
            || { echo "правило ipset не найдено в ufw-before-input (UFW выключен?)"; return 1; }
    else
        iptables -C SCANNERS-BLOCK -m set --match-set "$SET4" src -j DROP 2>/dev/null \
            || { echo "правило ipset не найдено в SCANNERS-BLOCK"; return 1; }
        iptables -C INPUT -j SCANNERS-BLOCK 2>/dev/null \
            || { echo "нет перехода INPUT -> SCANNERS-BLOCK"; return 1; }
    fi
    systemctl is-enabled antiscanner-ipset.service &>/dev/null \
        || { echo "antiscanner-ipset.service не включён"; return 1; }
    return 0
}

if [ -d "$BACKUP_DIR" ]; then
    if REASON=$(verify_migration); then
        rm -rf "$BACKUP_DIR"
        rmdir "$STATE_DIR/backup" 2>/dev/null
        echo -e "${B_GREEN}Миграция проверена, резервные копии удалены.${NC}"
    else
        echo -e "${B_YELLOW}Проверка не пройдена ($REASON), резервные копии оставлены: $BACKUP_DIR${NC}"
    fi
fi
