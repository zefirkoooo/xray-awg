# xray-awg
Xray VLESS + REALITY 443

# Информация
- установку и настройку Xray с поддержкой REALITY
- генерацию ключей и базового конфига
- добавление/удаление пользователей с отдельными конфигурационными файлами
- проверку конфигурации перед применением
- перезапуск сервиса Xray

# Функции
- **install** — установка Xray + настройка REALITY, генерация ключей и базового конфига
- **uninstall** — полное удаление Xray и конфигурационных файлов.
- **add-user** — добавление нового пользователя, создание отдельного клиентского `.json` с его ключами, вывод ссылки и пути к файлу.
- **remove-user** — удаление пользователя из конфигурации с выбором из списка.
- **автопроверка конфигурации** (`xray -test`) перед перезапуском сервиса.

# Требования 
- Linux (Debian/Ubuntu/Rocky/AlmaLinux и подобные)
- root-доступ
- systemd
- открытый порт (по умолчанию `443`)

# Установка
```bash
git clone https://github.com/username/xray-reality-manager.git
cd xray-reality-manager
chmod +x reality-manager.sh
./reality-manager.sh install
./reality-manager.sh add-user <user>
