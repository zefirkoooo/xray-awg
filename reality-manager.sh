#!/usr/bin/env bash
# Команды: install | add-user <name> | remove-user | uninstall | logs
# - Отдельные файлы клиентов: /usr/local/etc/xray/clients.d/<name>.json
# Debian/Ubuntu + systemd, требуется root.

set -euo pipefail

# ====== Параметры (можно переопределить env) ======
XRAY_PORT="${XRAY_PORT:-443}"                     # внешний TCP порт
REALITY_SNI="${REALITY_SNI:-www.cloudflare.com}"  # SNI «маскировки»
REALITY_SHORTID_LEN="${REALITY_SHORTID_LEN:-12}"  # 8..16 hex
XRAY_DIR="/usr/local/etc/xray"
CLIENTS_DIR="${XRAY_DIR}/clients.d"
BASE_CFG="${XRAY_DIR}/base.json"
MERGED_CFG="${XRAY_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
SID_FILE="${XRAY_DIR}/reality.sid"                # server shortId
PRIV_FILE="${XRAY_DIR}/reality.private"
PUB_FILE="${XRAY_DIR}/reality.public"
EXPORT_DIR="${EXPORT_DIR:-/root/reality_clients}" # профили для выдачи
LOG_DIR="/var/log/xray"
ACCESS_LOG="${LOG_DIR}/access.log"
ERROR_LOG="${LOG_DIR}/error.log"

# ====== Утилиты ======
has(){ command -v "$1" >/dev/null 2>&1; }
need_root(){ [ "$(id -u)" -eq 0 ] || { echo "Нужен root (sudo)"; exit 1; }; }
rand_hex(){ tr -dc 'a-f0-9' </dev/urandom | head -c "${1:-12}"; }
gen_uuid(){ cat /proc/sys/kernel/random/uuid; }
info(){ echo -e "\e[36m$*\e[0m"; }
warn(){ echo -e "\e[33m$*\e[0m" >&2; }
err(){ echo -e "\e[31m$*\e[0m" >&2; }

pub_ip(){
  local ip
  ip="$(curl -4sS --max-time 3 https://ifconfig.co 2>/dev/null || true)"
  [ -n "$ip" ] || ip="$(curl -4sS --max-time 3 https://ipinfo.io/ip 2>/dev/null || true)"
  [ -n "$ip" ] || ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}')" || true
  [ -n "$ip" ] || ip="YOUR_SERVER_IP"
  printf "%s" "$ip"
}

# ====== Гарантии окружения ======
ensure_deps(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y curl jq iptables sudo >/dev/null
}

ensure_xray(){
  if [ ! -x "$XRAY_BIN" ]; then
    info ">>> Установка Xray…"
    bash <(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) >/dev/null
  fi
  [ -x "$XRAY_BIN" ] || { err "Не найден бинарь $XRAY_BIN"; exit 1; }
}

ensure_dirs(){
  mkdir -p "$XRAY_DIR" "$CLIENTS_DIR" "$EXPORT_DIR"
  chmod 755 "$XRAY_DIR" "$CLIENTS_DIR"
  chmod 700 "$EXPORT_DIR"
}

ensure_logs(){
  mkdir -p "$LOG_DIR"
  touch "$ACCESS_LOG" "$ERROR_LOG"
  chown root:root "$LOG_DIR" "$ACCESS_LOG" "$ERROR_LOG"
  chmod 755 "$LOG_DIR"
  chmod 644 "$ACCESS_LOG" "$ERROR_LOG"
}

ensure_service_override(){
  mkdir -p /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service.d/override.conf <<'EOF'
[Service]
User=root
Group=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=no
EOF
  systemctl daemon-reload
}

ensure_keys(){
  if [ ! -s "$PRIV_FILE" ] || [ ! -s "$PUB_FILE" ]; then
    info ">>> Генерация ключей REALITY (x25519)…"
    umask 077
    local out priv pub
    out="$("$XRAY_BIN" x25519)"
    priv="$(echo "$out" | awk '/Private key:/{print $3}')"
    pub="$(echo  "$out" | awk '/Public key:/{print $3}')"
    [ -n "$priv" ] && [ -n "$pub" ] || { err "Не удалось сгенерировать x25519"; exit 1; }
    printf "%s\n" "$priv" > "$PRIV_FILE"
    printf "%s\n" "$pub"  > "$PUB_FILE"
    chmod 600 "$PRIV_FILE"
    chmod 644 "$PUB_FILE"
  fi
}

ensure_sid(){
  if [ ! -s "$SID_FILE" ]; then
    printf "%s" "$(rand_hex "$REALITY_SHORTID_LEN")" > "$SID_FILE"
    chmod 644 "$SID_FILE"
  fi
}

write_base_json(){
  local sid; sid="$(cat "$SID_FILE")"
  cat >"$BASE_CFG" <<JSON
{
  "log": { "access": "${ACCESS_LOG}", "error": "${ERROR_LOG}", "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": { "decryption": "none", "clients": [] },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_SNI}:443",
          "xver": 0,
          "serverNames": ["${REALITY_SNI}"],
          "privateKey": "$(cat "$PRIV_FILE")",
          "shortIds": ["${sid}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
JSON
  chmod 644 "$BASE_CFG"
}

ensure_base_json(){
  if [ ! -s "$BASE_CFG" ]; then
    info ">>> Создаю base.json…"
    write_base_json
  else
    if ! jq -e '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$BASE_CFG" >/dev/null 2>&1; then
      warn "base.json повреждён — пересоздаю"
      write_base_json
    fi
  fi
}

open_port(){
  if has iptables; then
    iptables -C INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT
    iptables-save >/etc/iptables.rules 2>/dev/null || true
  fi
}

test_config(){
  if ! "$XRAY_BIN" -test -c "$MERGED_CFG"; then
    err "Конфиг не прошёл проверку. Посмотри ${ERROR_LOG}"
    return 1
  fi
  return 0
}

safe_restart_xray(){
  test_config || return 1
  systemctl restart xray
}

merge_config(){
  local clients_json='[]'
  if [ -d "$CLIENTS_DIR" ] && ls -1 "$CLIENTS_DIR"/*.json >/dev/null 2>&1; then
    clients_json="$(jq -s '.' "$CLIENTS_DIR"/*.json)"
  fi
  jq --argjson clients "$clients_json" \
     '.inbounds[0].settings.clients = $clients' \
     "$BASE_CFG" > "${MERGED_CFG}.new"
  mv "${MERGED_CFG}.new" "$MERGED_CFG"
  chmod 644 "$MERGED_CFG"
  safe_restart_xray || {
    err "Рестарт Xray не выполнен (см. логи). Конфиг сохранён: $MERGED_CFG"
    return 1
  }
}

vless_link(){
  local uuid="$1"; local pbk="$2"; local sid="$3"
  printf "vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#FR-REALITY\n" \
    "$uuid" "$(pub_ip)" "$XRAY_PORT" "$REALITY_SNI" "$pbk" "$sid"
}

# ====== Команды ======
cmd_install(){
  need_root
  info ">>> Подготовка окружения…"
  ensure_deps
  ensure_xray
  ensure_dirs
  ensure_logs
  ensure_service_override
  ensure_keys
  ensure_sid
  ensure_base_json
  open_port

  info ">>> Первый запуск…"
  cp -f "$BASE_CFG" "$MERGED_CFG"
  chmod 644 "$MERGED_CFG"
  test_config
  systemctl enable xray >/dev/null || true
  systemctl restart xray

  info "Готово. Добавь пользователя:  $(basename "$0") add-user <name>"
}

cmd_add_user(){
  need_root
  local name="${1:-}"; [ -n "$name" ] || { echo "Использование: $(basename "$0") add-user <name>"; exit 1; }

  ensure_deps; ensure_xray; ensure_dirs; ensure_logs; ensure_service_override
  ensure_keys; ensure_sid; ensure_base_json

  local user_json="${CLIENTS_DIR}/${name}.json"
  [ -e "$user_json" ] && { err "Пользователь ${name} уже существует: $user_json"; exit 1; }

  local uuid; uuid="$(gen_uuid)"
  cat >"$user_json" <<JSON
{
  "id": "${uuid}",
  "flow": "xtls-rprx-vision",
  "email": "${name}@local"
}
JSON
  chmod 644 "$user_json"

  if ! merge_config; then
    err "Ошибка пересборки/рестарта. Проверь logs: $(basename "$0") logs"
    exit 1
  fi

  local sid pbk link export_file
  sid="$(cat "$SID_FILE")"
  pbk="$(cat "$PUB_FILE")"
  link="$(vless_link "$uuid" "$pbk" "$sid")"

  mkdir -p "$EXPORT_DIR"
  export_file="${EXPORT_DIR}/${name}.txt"
  cat >"$export_file" <<EOF
=== ${name} — VLESS REALITY (Vision) ===

Импортная ссылка (вставь целиком в v2rayN / v2rayNG):
${link}

Параметры для ручного ввода:
Server:    $(pub_ip)
Port:      ${XRAY_PORT} (TCP)
Protocol:  VLESS + REALITY (Vision)
UUID:      ${uuid}
PublicKey: ${pbk}
ShortID:   ${sid}
SNI:       ${REALITY_SNI}

Серверный объект клиента: ${user_json}
EOF
  chmod 600 "$export_file"

  echo
  echo "==== КОД ДЛЯ ПОДКЛЮЧЕНИЯ (импортируй как ссылку) ===="
  echo "${link}"
  echo "====================================================="
  echo "Путь к клиентскому файлу:  ${export_file}"
  echo "Путь к серверному объекту: ${user_json}"
  echo
  echo "Готово."
}

cmd_remove_user(){
  need_root
  ensure_dirs
  [ -d "$CLIENTS_DIR" ] || { err "Нет каталога ${CLIENTS_DIR}"; exit 1; }

  local pick=""
  if has fzf; then
    pick="$(ls -1 "$CLIENTS_DIR"/*.json 2>/dev/null | sed 's#.*/##; s#\.json$##' | fzf --prompt="Удалить пользователя > " || true)"
  else
    echo "Кого удалить? Введи номер:"
    select u in $(ls -1 "$CLIENTS_DIR"/*.json 2>/dev/null | sed 's#.*/##; s#\.json$##'); do pick="$u"; break; done
  fi
  [ -n "${pick:-}" ] || { echo "Ничего не выбрано."; exit 0; }

  rm -f "${CLIENTS_DIR}/${pick}.json"
  rm -f "${EXPORT_DIR}/${pick}.txt" 2>/dev/null || true
  if ! merge_config; then
    err "Удалил файл, но рестарт не прошёл. Проверь $(basename "$0") logs"
    exit 1
  fi
  echo "Удалён: ${pick}"
}

cmd_uninstall(){
  need_root
  info ">>> Остановка сервиса…"
  systemctl stop xray 2>/dev/null || true
  systemctl disable xray 2>/dev/null || true

  info ">>> Бэкап конфигов…"
  local stamp="/root/xray-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  if [ -d "$XRAY_DIR" ]; then
    tar czf "$stamp" -C "$(dirname "$XRAY_DIR")" "$(basename "$XRAY_DIR")" 2>/dev/null || true
    echo "Бэкап: $stamp"
  fi

  info ">>> Удаление файлов…"
  rm -f /etc/systemd/system/xray.service
  rm -rf "$CLIENTS_DIR" "$XRAY_DIR" "$EXPORT_DIR" 2>/dev/null || true
  rm -f "$XRAY_BIN" 2>/dev/null || true
  rm -rf "$LOG_DIR" 2>/dev/null || true
  systemctl daemon-reload
  warn "iptables-правила (если добавлялись) оставлены."
  echo "Готово."
}

cmd_logs(){
  need_root
  ensure_logs
  echo -e "\n=== tail -n 100 ${ERROR_LOG} ==="
  tail -n 100 "$ERROR_LOG" 2>/dev/null || true
  echo -e "\n=== tail -n 100 ${ACCESS_LOG} ==="
  tail -n 100 "$ACCESS_LOG" 2>/dev/null || true
  echo -e "\n=== systemd (journal) ==="
  journalctl -u xray -n 50 --no-pager || true
}

usage(){
  cat <<EOF
Использование: $(basename "$0") <команда> [аргументы]

Команды:
  install                 Установка/починка Xray + REALITY (лог-файлы, override, валидатор)
  add-user <name>         Добавить пользователя (печать vless:// и путей)
  remove-user             Удалить пользователя (список или fzf)
  uninstall               Снести установку и сделать бэкап
  logs                    Показать хвост логов (error/access + journal)

Переменные окружения:
  XRAY_PORT (по умолчанию 443)
  REALITY_SNI (по умолчанию www.cloudflare.com)
  REALITY_SHORTID_LEN (по умолчанию 12, допустимо 8..16)
  EXPORT_DIR (по умолчанию /root/reality_clients)
EOF
}

main(){
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    install)      cmd_install "$@" ;;
    add-user)     cmd_add_user "$@" ;;
    remove-user)  cmd_remove_user "$@" ;;
    uninstall)    cmd_uninstall "$@" ;;
    logs)         cmd_logs "$@" ;;
    ""|help|-h|--help) usage ;;
    *) err "Неизвестная команда: $cmd"; usage; exit 1;;
  esac
}

main "$@"
