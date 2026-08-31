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

echo -e "${B_CYAN}Конфигурация AntiScanner${NC}"
echo -e "Выберите метод защиты:"
echo -e "1) UFW (рекомендуется для Ubuntu/Debian)"
echo -e "2) iptables (прямые правила)"
read -p "Ваш выбор [1-2]: " FW_CHOICE

case $FW_CHOICE in
    1)
        MODE="ufw"
        # 1. Устанавливаем UFW, если его нет
        if ! command -v ufw >/dev/null; then
            echo -e "${B_YELLOW}Установка UFW...${NC}"
            apt-get update -qq && apt-get install -y ufw -qq
        fi

        # 2. Удаляем iptables-persistent, чтобы он не перезаписывал правила UFW
        if dpkg -l | grep -q iptables-persistent; then
            echo -e "${B_YELLOW}Удаление конфликтующего iptables-persistent...${NC}"
            apt-get purge -y iptables-persistent -qq
        fi
        ;;
    2)
        MODE="iptables"
        # Для чистого iptables нам как раз нужны утилиты сохранения
        echo -e "${B_YELLOW}Настройка компонентов iptables...${NC}"
        # Сообщаем системе, что установка будет неинтерактивной
        export DEBIAN_FRONTEND=noninteractive

        # Предустанавливаем ответы "Yes" (правда) для iptables-persistent
        mkdir -p /etc/iptables
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt-get update -qq && apt-get install -y curl iptables iptables-persistent -qq
        ;;
    *) echo "Неверный выбор. Выход."; exit 1 ;;
esac

# ============================================================
# Защита от аномальных TCP-флагов (NULL/Xmas/SYN-FIN/SYN-RST сканы)
# Статичные правила, не связаны с обновляемым блок-листом сканеров,
# поэтому применяются один раз здесь, а не в update-antiscanner.sh
# ============================================================

setup_tcp_flags_protection_iptables() {
    echo -e "${B_YELLOW}Установка защиты от аномальных TCP-флагов (iptables)...${NC}"
    for cmd in iptables ip6tables; do
        if ! $cmd -L TCP-FLAGS-PROTECT -n &>/dev/null; then
            $cmd -N TCP-FLAGS-PROTECT
        fi

        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL NONE -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL ALL -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
        $cmd -C TCP-FLAGS-PROTECT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 2>/dev/null || \
            $cmd -A TCP-FLAGS-PROTECT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

        # Подключаем цепочку к INPUT перед остальными правилами (в т.ч. перед SCANNERS-BLOCK)
        if ! $cmd -C INPUT -p tcp -j TCP-FLAGS-PROTECT &>/dev/null; then
            $cmd -I INPUT 1 -p tcp -j TCP-FLAGS-PROTECT
        fi
    done
}

setup_tcp_flags_protection_ufw() {
    echo -e "${B_YELLOW}Установка защиты от аномальных TCP-флагов (UFW before.rules)...${NC}"
    for RULES_FILE in /etc/ufw/before.rules /etc/ufw/before6.rules; do
        [ -f "$RULES_FILE" ] || continue

        # Не дублируем при повторном запуске скрипта
        if grep -q "AntiScanner-TCP-Flags" "$RULES_FILE"; then
            continue
        fi

        # Имя цепочки в before6.rules отличается от before.rules (префикс ufw6-)
        if [[ "$RULES_FILE" == *before6.rules ]]; then
            CHAIN="ufw6-before-input"
        else
            CHAIN="ufw-before-input"
        fi

        # Вставляем блок правил перед первой строкой COMMIT (конец секции *filter)
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

        mv "$TMP_FILE" "$RULES_FILE"
    done
}

if [ "$MODE" = "iptables" ]; then
    setup_tcp_flags_protection_iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    # Без этого сервиса rules.v4/rules.v6 не восстановятся после ребута —
    # apt install не всегда сам включает автозагрузку сервиса
    systemctl enable netfilter-persistent 2>/dev/null || systemctl enable iptables-persistent 2>/dev/null
    systemctl restart netfilter-persistent 2>/dev/null

    if systemctl is-enabled netfilter-persistent &>/dev/null; then
        echo -e "${B_GREEN}netfilter-persistent включён — правила переживут перезагрузку.${NC}"
    else
        echo -e "${B_RED}ВНИМАНИЕ: не удалось включить netfilter-persistent. После ребута правила iptables могут слететь!${NC}"
        echo -e "${B_YELLOW}Проверьте вручную: systemctl status netfilter-persistent${NC}"
    fi
else
    setup_tcp_flags_protection_ufw

    # before.rules применяется при каждом старте ufw — убеждаемся, что сам ufw в автозагрузке
    systemctl enable ufw 2>/dev/null

    if systemctl is-enabled ufw &>/dev/null; then
        echo -e "${B_GREEN}UFW включён в автозагрузку — before.rules применится при ребуте.${NC}"
    else
        echo -e "${B_RED}ВНИМАНИЕ: ufw не в автозагрузке. Выполните: ufw enable${NC}"
    fi
fi

apt-get install -y logrotate -qq

# --- Ротация логов: храним только последние 7 дней, чтобы не раздувать диск ---
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

S="/usr/local/bin/update-antiscanner.sh"

cat << 'EOF' > "$S"
#!/bin/bash
URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
TEMP_FILE=$(mktemp)
MODE="__MODE_PLACEHOLDER__"

setup_iptables_chains() {
    for cmd in iptables ip6tables; do
        if ! $cmd -L SCANNERS-BLOCK -n &>/dev/null; then
            $cmd -N SCANNERS-BLOCK
        else
            $cmd -F SCANNERS-BLOCK
        fi
        if ! $cmd -C INPUT -j SCANNERS-BLOCK &>/dev/null; then
            $cmd -I INPUT 1 -j SCANNERS-BLOCK
        fi
    done
}

if curl -sSL --max-time 30 "$URL" -o "$TEMP_FILE" && [[ -s "$TEMP_FILE" ]]; then
    if [ "$MODE" = "ufw" ]; then
        sed -i '/AntiScanner-Block/d' /etc/ufw/user.rules
        sed -i '/AntiScanner-Block/d' /etc/ufw/user6.rules
        while IFS= read -r subnet; do
            # 1. Убираем лишние пробелы по краям
            subnet=$(echo "$subnet" | xargs)

            # 2. Пропускаем пустые строки и комментарии
            [[ -z "$subnet" || "$subnet" == "#"* ]] && continue

            # 3. Базовая проверка, что это похоже на IP (содержит точку или двоеточие)
            if [[ "$subnet" =~ : ]]; then
                ufw deny from "$subnet" comment 'AntiScanner-Block'
            elif [[ "$subnet" =~ \. ]]; then
                ufw prepend deny from "$subnet" comment 'AntiScanner-Block'
            else
                echo "Пропуск: $subnet"
            fi
        done < "$TEMP_FILE"
        ufw reload
    else
        setup_iptables_chains
        while IFS= read -r subnet; do
            [[ -z "$subnet" || "$subnet" == "#"* ]] && continue
            if [[ "$subnet" =~ : ]]; then
                ip6tables -A SCANNERS-BLOCK -s "$subnet" -j DROP
            else
                iptables -A SCANNERS-BLOCK -s "$subnet" -j DROP
            fi
        done < "$TEMP_FILE"
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Список AntiScanner обновлён"
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Не удалось скачать список AntiScanner, оставляю текущие правила без изменений"
fi
rm -f "$TEMP_FILE"
EOF

# Подстановка режима в созданный скрипт
sed -i "s/__MODE_PLACEHOLDER__/$MODE/" "$S"

chmod +x "$S"
$S

C_JOB="20 3 * * * $S >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null | grep -v "$S" ; echo "$C_JOB") | crontab -

read -p $'\033[1;33mСоздать службу systemd для обновления при старте системы? [y/N]: \033[0m' SYSTEMD_CHOICE
if [[ "$SYSTEMD_CHOICE" =~ ^[Yy]$ ]]; then
    cat << EOF > /etc/systemd/system/antiscanner-update.service
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network.target

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

echo -e "${B_GREEN}AntiScanner успешно настроен через $MODE!${NC}"
echo -e "${B_GREEN}Защита от аномальных TCP-флагов активна (цепочка TCP-FLAGS-PROTECT / before.rules).${NC}"
