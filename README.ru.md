# vpnchecker

[English version](README.md)

VPN kill switch для macOS. Исходящий трафик разрешён **только через VPN-интерфейс**; без VPN в интернет не уходит ничего, кроме самого VPN-клиента (портал / шлюзы) и локальной сети. Сделан под GlobalProtect, работает с любым VPN, создающим интерфейс `utunN`.

## Как это работает

Демон постоянно держит набор правил [pf](https://man.openbsd.org/pf.conf) в якоре `com.apple/vpnchecker` (стандартный `/etc/pf.conf` уже подключает `com.apple/*`, системный конфиг не меняется):

```
pass out quick on lo0 all                                # localhost
pass out quick on utun4 all keep state (if-bound)        # туннель
pass out quick proto { tcp udp } to any port 53          # DNS
pass out quick proto udp to any port { 67 68 123 546 547 }  # DHCP, NTP
pass out quick inet6 proto icmp6 all                     # IPv6 neighbor discovery
pass out quick to <vpnchecker_allow>                     # портал/шлюзы VPN, LAN
block return out quick all                               # всё остальное
```

macOS выбирает интерфейс до того, как пакет попадает в pf. Пока VPN поднят, маршрут по умолчанию идёт через `utun4` и трафик проходит. Когда VPN падает, маршрут переключается на `en0`, и **ядро блокирует первый же пакет** — окна нет, скорость реакции демона не важна.

Демон:

- **Следит за VPN-интерфейсом.** VPN поднят, если интерфейс по `interface_pattern` имеет адрес из `vpn.subnets` **и** маршрут по умолчанию идёт через него (GlobalProtect оставляет `utunN` с адресом из пула после отключения, одного интерфейса недостаточно). Проверка запускается сразу при каждом изменении маршрутов / адресов / интерфейсов в ядре (`PF_ROUTE` socket) и раз в `check.interval` как запасной вариант. Если интерфейс сменился (`utun4` → `utun5`), правило переписывается.
- **Держит allowlist актуальным**, чтобы VPN-клиент мог переподключиться, пока всё заблокировано:
  - `allow.domains` покрывают домен **и все его поддомены**. Демон поднимает DNS-форвардер на `127.0.0.1:10053` и пишет `/etc/resolver/<домен>` для каждой записи, поэтому любой запрос под этим доменом идёт через форвардер; адреса из ответа попадают в pf-таблицу allowlist *до того*, как ответ получит приложение. Вышестоящий DNS выбирается для каждого запроса из `scutil --dns` (split DNS VPN продолжает работать). Сами домены также перерезолвятся каждые `resolve_interval` и сразу после падения VPN (split-horizon DNS отвечает по-разному в VPN и вне его);
  - `allow.globalprotect` находит портал (`Portal` / `LastUrl` в plist-настройках GlobalProtect) и шлюзы (имена хостов в `pan_gp_event.log`). Пока VPN лежит, лог отслеживается на каждой проверке, поэтому шлюз, к которому клиент только начал подключаться, разрешается за секунды;
  - `allow.learn_gateways` добавляет шлюзы VPN, видимые как host-маршруты в обход туннеля, пока VPN поднят;
  - каждый увиденный адрес хранится `resolve_retain` и сохраняется в `/var/db/vpnchecker/cache.json`.
- **Обрывает соединения туннеля** (pf-состояния из `vpn.subnets`) при падении VPN; правило туннеля использует `if-bound` состояния, поэтому ни одно соединение не может «перетечь» на `en0`.
- **Переживает собственный выход.** По `SIGTERM` / `SIGINT` (остановка через launchd, `kill`) оставляет правила, пропускающие только трафик *с адресов `vpn.subnets`* — то есть идущий через туннель: интернет сам вернётся, когда VPN переподключится, и останется заблокированным без него. При падении или `SIGKILL` в pf просто остаются последние загруженные правила. В обоих случаях launchd перезапускает демон.
- **Уведомляет** (уведомление macOS), когда VPN поднимается / падает.

## Требования

- macOS (Apple Silicon или Intel)
- `sudo` для установки (pf требует root)

## Установка

Подключите VPN и выполните:

```sh
curl -fsSL https://github.com/pwyllcrusader/vpnchecker/releases/latest/download/install.sh | sh
```

Скрипт скачивает готовый универсальный бинарник из последнего GitHub-релиза, проверяет контрольную сумму, создаёт `~/.config/vpnchecker/config.yaml`, если его нет, отказывается продолжать, если VPN не обнаружен (иначе пропал бы интернет), выполняет `sudo vpnchecker install` и создаёт ссылку `/usr/local/bin/vpnchecker`. Для обновления запустите ту же команду. Если пул адресов VPN не `10.0.0.0/8`, укажите `vpn.subnets` в конфиге и запустите ещё раз.

### Из исходников

```sh
cargo install vpnchecker      # или из исходников: cargo install --path .

# 1. Создать конфиг и заполнить vpn.subnets и allow.* (см. Конфигурация)
vpnchecker config init
$EDITOR ~/.config/vpnchecker/config.yaml
vpnchecker config validate

# 2. Проверить детекцию (VPN подключён)
vpnchecker diagnose

# 3. Установить как launchd-демон
sudo "$(which vpnchecker)" install
vpnchecker status
```

`install` копирует **запущенный** бинарник в `/Library/PrivilegedHelperTools/vpnchecker` (владелец `root:wheel`, обычный пользователь не сможет его подменить), пишет `/Library/LaunchDaemons/com.vpnchecker.daemon.plist` и запускает демон. Он стартует при загрузке и перезапускается, если завершился. С `sudo` используйте полный путь — у sudo свой `PATH`. После каждого обновления повторяйте `install`.

## Команды

| Команда | Root | Описание |
|---|---|---|
| `install` / `uninstall` | да | Установка / удаление launchd-демона (`uninstall` также снимает pf-правила) |
| `start` / `restart` | да | Запуск / перезапуск установленного демона |
| `stop [--keep-block]` | да | Остановить демон и снять его pf-правила (`--keep-block` оставляет правила выхода) |
| `flush` | да | Немедленно снять pf-правила vpnchecker |
| `status [--json]` | нет | Состояние VPN, интерфейс, размер allowlist, проверки |
| `check [-q]` | нет | Разовая проверка VPN. Код возврата: `0` поднят, `1` упал, `2` ошибка |
| `diagnose` | нет | Интерфейсы, проверки, резолв доменов allowlist, найденные хосты GlobalProtect, запомненные шлюзы VPN |
| `reload` | владелец | Перечитать конфиг в работающем демоне (аналог `SIGHUP`) |
| `allow <домен\|URL>` | владелец | Добавить домен (с поддоменами) в `allow.domains` конфига, сохранив комментарии, и перечитать конфиг в демоне |
| `logs [-f] [-n N]` | нет | Показать `/var/log/vpnchecker.log` |
| `config init [--force]` / `validate` / `path` | нет | Работа с конфигом |
| `run [--dry-run]` | да (нет с `--dry-run`) | Запуск в foreground. `--dry-run` пишет правила в лог вместо применения |

Глобальные опции: `--config <path>` (переменная `VPNCHECKER_CONFIG`), `--socket <path>` (по умолчанию `/var/run/vpnchecker.sock`), `-v`/`-vv`.

## Конфигурация

Путь: `~/.config/vpnchecker/config.yaml`. Неизвестные поля отклоняются. Пример: [config.example.yaml](config.example.yaml).

```yaml
vpn:
  interface_pattern: '^(utun\d+|gpd\d+)$'   # GlobalProtect: utunN (старые версии: gpd0)
  subnets: [10.4.0.0/16, 10.5.0.0/16]       # пул адресов VPN, обязательно

allow:
  lan: true                  # RFC1918, link-local, multicast, IPv6 ULA
  learn_gateways: true       # автоматически разрешать шлюзы VPN из таблицы маршрутов
  globalprotect: true        # автоматически разрешать портал/шлюзы из настроек и лога GlobalProtect
  domains:                   # разрешены без VPN, вместе со всеми поддоменами
    - vpn.example.corp
    - example.com            # а также www.example.com, api.example.com, ...
  cidrs: [203.0.113.5/32]

check:
  interval: 2s               # запасной опрос
  timeout: 1500ms
  resolve_interval: 60s
  resolve_retain: 24h

notify: true
```

**Что добавлять в `allow`:** для самого VPN с GlobalProtect обычно ничего — `globalprotect` и `learn_gateways` сами находят портал и шлюзы (проверьте `vpnchecker diagnose`). Вручную добавляйте то, чего они не видят (другие VPN-клиенты, провайдер идентификации, если SAML-логин открывает его страницу при лежащем туннеле), и сервисы, которые должны работать без VPN: `vpnchecker allow telegram.org`.

**`vpn.subnets`:** пул адресов, который выдаёт VPN. Посмотрите адрес `utunN` при подключённом VPN (`ifconfig`); GlobalProtect также хранит ранее выданные адреса в `defaults read /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings` (`PreferredIP_*`).

Конфиг читается процессом от root, но ничего не может выполнить: в нём только шаблоны интерфейсов, хосты, подсети и тайминги. Лог GlobalProtect доступен пользователю на запись, поэтому `globalprotect: true` доверяет пользователю ровно настолько же, насколько и файл конфига.

## Проверка

```sh
vpnchecker status
sudo pfctl -a com.apple/vpnchecker -sr     # правила загружены всегда, с VPN и без
```

Отключите VPN: `curl -m5 https://example.com` должен сразу упасть, `vpnchecker status` показывает `Down`. Подключите снова: VPN должен подняться, трафик — пойти.

## Решение проблем

- **VPN не переподключается при блоке** — клиенту нужен адрес не из allowlist (новый шлюз, IdP для SAML). Выполните `sudo vpnchecker stop` (снимает правила), подключитесь, найдите хост через `vpnchecker diagnose` и лог GlobalProtect, добавьте в `allow`, `sudo vpnchecker start`.
- **Captive portal** (отели, аэропорты) — без VPN страница логина заблокирована: закройте приложения, которые не должны ходить напрямую, `sudo vpnchecker stop`, залогиньтесь, `sudo vpnchecker start`.
- **Демон не стартует** — `vpnchecker logs`. Ошибка `unknown field` значит, что установленный бинарник старее конфига: переустановите `sudo "$(which vpnchecker)" install`.
- **Удаление** — `sudo vpnchecker uninstall` удаляет демон, plist, бинарник и pf-правила, освобождает pf-токен.

## Хук Claude Code (опционально)

pf и так блокирует трафик, но хук даёт понятное сообщение вместо сетевой ошибки. В `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "vpnchecker check -q || { echo 'VPN is down, request blocked by vpnchecker' >&2; exit 2; }"
          }
        ]
      }
    ]
  }
}
```

## Ограничения

- **Только full tunnel:** трафик, который VPN пускает мимо туннеля (исключения split-tunnel), блокируется.
- **Без защиты, пока демон остановлен:** `stop`, `flush` и `uninstall` снимают правила, а после перезагрузки ничего не фильтруется, пока launchd не запустит демон. Перед остановкой закройте приложения, которые не должны ходить напрямую.
- **Не по процессам:** правила действуют на всю машину. Фильтрация по процессу требует NetworkExtension.
- **DNS** (порт 53) разрешён к любому серверу, поэтому при лежащем VPN запросы имён уходят локальному резолверу.
- **Приложения со своим DNS** (DoH, зашитые резолверы) обходят `/etc/resolver`: поддомены разрешённых доменов, которые они резолвят, не запоминаются и остаются заблокированными.
- **IPv6:** блокируется, если не идёт через туннель или в allowlist.

## Разработка

```sh
cargo test
cargo clippy --all-targets
vpnchecker --socket /tmp/vpnchecker.sock run --dry-run -v
```

Релиз: поднять `version` в `Cargo.toml`, закоммитить, `git tag vX.Y.Z && git push --tags`. Workflow `release` соберёт универсальный бинарник и выложит его вместе с `install.sh` в GitHub Releases.

## Лицензия

На выбор: [Apache License, Version 2.0](LICENSE-APACHE) или [MIT](LICENSE-MIT).
