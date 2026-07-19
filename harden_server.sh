#!/bin/bash
#
# harden_server.sh — интерактивная настройка базовой защиты Linux-сервера
#   1. Создание пользователя + пароль (openssl 16 симв. / ручной ввод)
#   2. Инструкция и мастер добавления SSH-ключей
#   3. Установка и настройка UFW (22/tcp открыт, задел под VPN)
#   4. Безопасное отключение парольного входа по SSH после проверки ключей
#
# Запуск: sudo bash harden_server.sh

set -euo pipefail

# ---------- Цвета ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[ERR]${NC} $1"; }

confirm() {
    # confirm "Текст вопроса" -> возвращает 0 если да
    local prompt="$1"
    local answer
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]: ${NC}")" answer
    [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

if [[ $EUID -ne 0 ]]; then
    err "Скрипт нужно запускать от root (sudo bash harden_server.sh)"
    exit 1
fi

echo "=================================================="
echo "   Мастер базовой защиты сервера"
echo "=================================================="
echo

##############################################
# 1. Создание пользователя
##############################################
info "Шаг 1. Создание пользователя"

while true; do
    read -r -p "Введите имя нового пользователя: " USERNAME
    if [[ -z "$USERNAME" ]]; then
        err "Имя не может быть пустым"
        continue
    fi
    if id "$USERNAME" &>/dev/null; then
        warn "Пользователь '$USERNAME' уже существует."
        if confirm "Продолжить с этим пользователем (без создания)?"; then
            USER_EXISTS=1
            break
        else
            continue
        fi
    fi
    USER_EXISTS=0
    break
done

if [[ "$USER_EXISTS" -eq 0 ]]; then
    useradd -m -s /bin/bash "$USERNAME"
    ok "Пользователь '$USERNAME' создан"
fi

if confirm "Добавить '$USERNAME' в группу sudo (права администратора)?"; then
    usermod -aG sudo "$USERNAME"
    ok "Пользователь добавлен в группу sudo"
fi

echo
info "Шаг 1.1. Установка пароля"
echo "  1) Сгенерировать случайный пароль (openssl, 16 символов)"
echo "  2) Ввести пароль вручную"
read -r -p "Выберите вариант [1/2]: " PASS_CHOICE

if [[ "$PASS_CHOICE" == "1" ]]; then
    PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c16)
    echo "$USERNAME:$PASSWORD" | chpasswd
    ok "Пароль сгенерирован и установлен"
    echo -e "${GREEN}Логин:   ${NC}$USERNAME"
    echo -e "${GREEN}Пароль:  ${NC}$PASSWORD"
    warn "Сохраните пароль сейчас — он больше не будет показан."
else
    while true; do
        read -r -s -p "Введите пароль: " P1; echo
        read -r -s -p "Повторите пароль: " P2; echo
        if [[ "$P1" != "$P2" ]]; then
            err "Пароли не совпадают, попробуйте снова"
            continue
        fi
        if [[ ${#P1} -lt 8 ]]; then
            warn "Пароль короче 8 символов, это небезопасно."
            if ! confirm "Всё равно использовать этот пароль?"; then
                continue
            fi
        fi
        echo "$USERNAME:$P1" | chpasswd
        ok "Пароль установлен"
        break
    done
fi

##############################################
# 2. SSH-ключи
##############################################
echo
info "Шаг 2. Настройка SSH-ключей"

USER_HOME=$(eval echo "~$USERNAME")
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
touch "$AUTH_KEYS"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
ok "Директория $SSH_DIR подготовлена"

cat <<EOF

--------------------------------------------------------
 Как забрать ключ с ваших машин (со всех, откуда будете
 подключаться к серверу):

 Вариант A — если на клиентской машине ключа ещё нет:
   ssh-keygen -t ed25519 -C "$USERNAME@$(hostname)"
   (жмите Enter на все вопросы, либо задайте passphrase)
   ssh-copy-id -i ~/.ssh/id_ed25519.pub $USERNAME@$(hostname -I | awk '{print $1}')

 Вариант B — если ключ уже есть:
   ssh-copy-id $USERNAME@<IP_этого_сервера>

 Вариант C — вручную (если ssh-copy-id недоступен, Windows и т.п.):
   1. На клиенте выполните: cat ~/.ssh/id_ed25519.pub
      (в Windows/PuTTY — содержимое .pub файла из PuTTYgen)
   2. Скопируйте одну строку целиком (начинается с ssh-ed25519 / ssh-rsa)
   3. Вставьте её ниже в этот скрипт, когда будет предложено
--------------------------------------------------------

EOF

while true; do
    if confirm "Добавить публичный ключ прямо сейчас (вставить строку)?"; then
        read -r -p "Вставьте публичный ключ целиком: " PUBKEY
        if [[ "$PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ssh-ed25519|ecdsa-sha2) ]]; then
            echo "$PUBKEY" >> "$AUTH_KEYS"
            ok "Ключ добавлен в $AUTH_KEYS"
        else
            err "Строка не похожа на валидный публичный ключ, пропущено"
        fi
    else
        break
    fi
    if ! confirm "Добавить ещё один ключ (с другой машины)?"; then
        break
    fi
done

chmod 600 "$AUTH_KEYS"
chown "$USERNAME:$USERNAME" "$AUTH_KEYS"

if [[ -s "$AUTH_KEYS" ]]; then
    ok "В authorized_keys уже есть $(wc -l < "$AUTH_KEYS") ключ(ей)"
else
    warn "Ключей пока не добавлено. Отключать вход по паролю НЕЛЬЗЯ, пока ключ не добавлен и не проверен."
fi

##############################################
# 3. UFW
##############################################
echo
info "Шаг 3. Настройка firewall (UFW)"

if ! command -v ufw &>/dev/null; then
    info "UFW не установлен, устанавливаю..."
    apt-get update -qq
    apt-get install -y ufw
    ok "UFW установлен"
else
    ok "UFW уже установлен"
fi

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH - временно, потом заменить на VPN-порт'
ok "Правило для 22/tcp (SSH) добавлено"

if ! ufw status | grep -q "Status: active"; then
    ufw --force enable
    ok "UFW включён"
else
    ok "UFW уже активен"
fi

echo
ufw status verbose
echo

cat <<'EOF'
--------------------------------------------------------
 Шпаргалка по UFW:
   sudo ufw status verbose        — посмотреть правила
   sudo ufw allow <порт>/tcp      — открыть порт (например 443)
   sudo ufw delete allow <порт>/tcp — закрыть порт
   sudo ufw deny <порт>/tcp       — явно заблокировать порт
   sudo ufw disable               — выключить firewall
   sudo ufw enable                — включить firewall
   sudo ufw reload                — применить изменения

 Когда поднимете VPN (WireGuard/OpenVPN), не забудьте:
   1. sudo ufw allow <порт_VPN>/udp (или tcp)
   2. Ограничить 22 порт только локальной VPN-подсетью, например:
        sudo ufw delete allow 22/tcp
        sudo ufw allow from 10.0.0.0/24 to any port 22 proto tcp
--------------------------------------------------------
EOF

##############################################
# 4. Отключение пароля после проверки ключей
##############################################
echo
info "Шаг 4. Отключение входа по паролю (только после проверки ключа!)"

warn "ПЕРЕД тем как продолжить: откройте НОВОЕ окно терминала (не закрывая текущую сессию!)"
warn "и убедитесь, что вход по ключу работает:"
echo "    ssh $USERNAME@<IP_сервера>"
echo
warn "Если вход по ключу НЕ работает — не отключайте пароль, иначе рискуете потерять доступ к серверу."
echo

if confirm "Вы проверили вход по ключу в отдельном окне и он РАБОТАЕТ? Отключить пароль?"; then
    if [[ ! -s "$AUTH_KEYS" ]]; then
        err "authorized_keys пуст — отключать пароль отказываюсь."
    else
        SSHD_CONFIG="/etc/ssh/sshd_config"
        cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
        ok "Сделан бэкап $SSHD_CONFIG"

        sed -i -E 's/^#?PasswordAuthentication\s+.*/PasswordAuthentication no/' "$SSHD_CONFIG"
        grep -q '^PasswordAuthentication' "$SSHD_CONFIG" || echo "PasswordAuthentication no" >> "$SSHD_CONFIG"

        if confirm "Также запретить root-вход по SSH (PermitRootLogin no)?"; then
            sed -i -E 's/^#?PermitRootLogin\s+.*/PermitRootLogin no/' "$SSHD_CONFIG"
            grep -q '^PermitRootLogin' "$SSHD_CONFIG" || echo "PermitRootLogin no" >> "$SSHD_CONFIG"
        fi

        if sshd -t; then
            ok "Конфиг sshd прошёл проверку синтаксиса"
            systemctl restart sshd 2>/dev/null || systemctl restart ssh
            ok "SSH перезапущен. Вход по паролю отключён."
            warn "НЕ закрывайте текущую root-сессию, пока не убедитесь, что новое подключение по ключу проходит."
        else
            err "Ошибка в конфиге sshd! Восстанавливаю бэкап, пароль НЕ отключён."
            cp "${SSHD_CONFIG}.bak."* "$SSHD_CONFIG" 2>/dev/null || true
        fi
    fi
else
    warn "Пропущено. Вход по паролю остаётся включённым. Запустите скрипт повторно позже, когда будете готовы."
fi

echo
echo "=================================================="
ok "Готово. Итоги:"
echo "  - Пользователь:        $USERNAME"
echo "  - SSH-ключей добавлено: $(wc -l < "$AUTH_KEYS" 2>/dev/null || echo 0)"
echo "  - UFW:                 активен, открыт порт 22"
echo "  - Парольный SSH-вход:  проверьте вывод шага 4 выше"
echo "=================================================="
