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
        
        # Устанавливаем только Curl
        apt-get install -y curl -qq
        ;;
    2) 
        MODE="iptables"
        # Для чистого iptables нам как раз нужны утилиты сохранения
        echo -e "${B_YELLOW}Настройка компонентов iptables...${NC}"
        apt-get update -qq && apt-get install -y curl iptables iptables-persistent -qq
        ;;
    *) echo "Неверный выбор. Выход."; exit 1 ;;
esac

S="/usr/local/bin/update-antiscanner.sh"
cat << EOF > "$S"
#!/bin/bash
URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
TEMP_FILE=\$(mktemp)
MODE="$MODE"

setup_iptables_chains() {
    for cmd in iptables ip6tables; do
        if ! \$cmd -L SCANNERS-BLOCK -n &>/dev/null; then
            \$cmd -N SCANNERS-BLOCK
        else
            \$cmd -F SCANNERS-BLOCK
        fi
        if ! \$cmd -C INPUT -j SCANNERS-BLOCK &>/dev/null; then
            \$cmd -I INPUT 1 -j SCANNERS-BLOCK
        fi
    done
}

if curl -sSL "\$URL" -o "\$TEMP_FILE" && [[ -s "\$TEMP_FILE" ]]; then
    if [ "\$MODE" = "ufw" ]; then
        sed -i '/AntiScanner-Block/d' /etc/ufw/user.rules
        sed -i '/AntiScanner-Block/d' /etc/ufw/user6.rules
        while IFS= read -r subnet; do
            # 1. Убираем лишние пробелы по краям
            subnet=$(echo "$subnet" | xargs)
            
            # 2. Пропускаем пустые строки и комментарии
            [[ -z "$subnet" || "$subnet" == "#"* ]] && continue
            
            # 3. Базовая проверка, что это похоже на IP (содержит точку или двоеточие)
            if [[ "$subnet" =~ \. || "$subnet" =~ : ]]; then
                ufw insert 1 deny from "$subnet" comment 'AntiScanner-Block'
            else
                echo "Пропуск: $subnet"
            fi
        done < "$TEMP_FILE"
        ufw reload
    else
        setup_iptables_chains
        while IFS= read -r subnet; do
            [[ -z "\$subnet" || "\$subnet" == "#"* ]] && continue
            if [[ "\$subnet" =~ : ]]; then
                ip6tables -A SCANNERS-BLOCK -s "\$subnet" -j DROP
            else
                iptables -A SCANNERS-BLOCK -s "\$subnet" -j DROP
            fi
        done < "\$TEMP_FILE"
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    fi
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] AntiScanner updated via \$MODE"
fi
rm -f "\$TEMP_FILE"
EOF

chmod +x "$S"
$S
C_JOB="20 3 * * * $S >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null | grep -v "$S" ; echo "$C_JOB") | crontab -

read -p "Создать службу systemd для обновления при старте системы? [y/N]: " SYSTEMD_CHOICE
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
