# epkg-tools

**Пакетный менеджер уровня apk-tools (Alpine Linux) для хобби-операционных
систем.** Пишешь свою ОС — подключаешь epkg, и `epkg install nano`
скачивает, проверяет и распаковывает пакеты прямо в ней, из обычного
GitHub-репозитория.

```
+-----------------+      HTTPS/HTTP       +---------------------------+
|  твоя хобби-ОС  | <-------------------> |  GitHub-репозиторий       |
|  epkg install x |   raw / Releases /    |  index.json + packages/   |
+-----------------+   любые зеркала       +---------------------------+
```

## Возможности

* **Ядро C99 freestanding** — ни libc, ни syscall'ов; вся система
  выходит через порт-слой из ~25 функций (`include/epk_port.h`).
* **HTTPS из коробки** — вендоренный [BearSSL](https://www.bearssl.org)
  (MIT): TLS 1.2, ECDHE + AES-GCM, проверка цепочки X.509 по PEM-бандлу
  корневых сертификатов (`ca/roots.pem`, Mozilla CA store).
* **Формат пакета** — честный `tar.gz` с `PKGINFO`: двухуровневая
  проверка целостности (sha256 пакета в индексе + манифест-хеш файлов
  в PKGINFO). Поддержка symlink-записей tar. См. `FORMAT.md`.
* **Репозиторий = GitHub**: `index.json` + каталог `packages/`.
  Работает через raw.githubusercontent.com, GitHub Releases (поле
  `url`) и любые зеркала (jsDelivr, локальный http-сервер для QEMU).
* **Dep-resolution v2** — автоматическое разрешение зависимостей:
  topo-сортировка (зависимости ставятся первыми), версии-ограничения
  (`libc>=2.0`, `libfoo = 1.1`, `bar<2`), обнаружение циклов
  (`a -> b -> a`), отчёт о недостающих пакетах, предупреждение об
  обратных зависимостях при `remove`. `--no-deps` возвращает прежнее
  поведение «только предупреждение».
* **epkg upgrade поверх v2-резолвера** — world-файл (как в apk):
  явно установленные пакеты попадают в `<db>/world`, и
  `epkg upgrade` без аргументов обновляет всё устаревшее разом.
  Устаревшая зависимость не роняет транзакцию, а подтягивается до
  версии из индекса (chained upgrade: новое `app` само обновит
  требуемый `libfoo`).
* **Genesis-bootstrap образа** — `epkg install --root /mnt/image ...`
  ставит пакеты в чистый образ вашей ОС: БД, кеш и world лежат внутри
  образа (`<root>/var/lib/epkg`, `<root>/var/cache/epkg`). На реальной
  системе epkg работает так же, только `--root` не указывается.
* **Докачка при обрыве** — прерванная загрузка сохраняет
  `<файл>.part` в кеше и продолжается с места разрыва через
  HTTP `Range` (в том числе между запусками epkg и между зеркалами;
  корректность гарантирует итоговая проверка sha256).
* **epkg audit — подписи индекса (signify/ed25519)** — репозиторий
  подписывается ключом Ed25519 в формате signify: `epkg update`
  автоматически проверяет подпись `index.sig` по закреплённому в
  `epkg.conf` pubkey (strict: несовпадение = отказ зеркала), а
  `epkg audit` проверяет кеш, зеркало или произвольный файл вручную.
  Реализация Ed25519 (RFC 8032) — своя, чистый C99 без зависимостей,
  проверена векторами RFC 8032 и кросс-чеком с OpenSSL; файлы
  `.pub`/`.sig` совместимы с OpenBSD signify.
* **Symlink-политика** — `symlinks = deny` (по умолчанию: symlink'ы
  из пакетов пропускаются с предупреждением) или `symlinks = keep`
  (создавать как есть; записываются в БД и удаляются при remove).
  Защита от классической tar-symlink-атаки.
* **Команды**: `update search info deps install upgrade remove list fetch audit version`.
* **Свои пакеты одной командой**: `mkepkg pkgdir` собирает `.epkg`,
  сам считает манифест-хеш и пакует symlink'и.
* **Свои ключи одной командой**: `epkg-key gen/sign/verify/fp` —
  signify-совместимые ключи и подписи для индекса.
* **Публикация репозитория на GitHub одной командой** —
  `scripts/publish-sample-repo.sh <git-url>` собирает пакеты,
  генерирует index.json и пушит их в ваш репозиторий.

## Быстрый старт (POSIX-хост: Linux / macOS / BSD)

```sh
make                 # соберёт epkg, mkepkg и epkg-key
make test            # юнит-тесты + e2e: dep-resolution v2, upgrade,
                     # symlink-политика, genesis --root, докачка,
                     # подписи индекса (epkg audit)

# свой мини-репозиторий в sample-repo/ (подписанный) и установка из него:
sh tools/build-sample.sh
cat > epkg.conf <<'EOF'
mirror = http://127.0.0.1:8000          # подними python3 -m http.server
db     = /tmp/epkg/db
cache  = /tmp/epkg/cache
root   = /tmp/epkg/root/
pubkey = sample-repo/demo.pub           # проверять подпись индекса
EOF
(cd sample-repo && python3 -m http.server 8000 &)
epkg update && epkg install hello && epkg list

# репозиторий опубликован раньше, а с тех пор вышел hello 1.1?
epkg update && epkg upgrade
```

## Зависимости и политики

```sh
epkg install app          # подтянет libfoo и libbar сама, по topo-порядку
epkg deps app             # покажет план установки, ничего не делая
epkg install app --no-deps  # ставить только запрошенное (v1-режим)
```

Политика symlink'ов — ключ `symlinks` в `epkg.conf` (или переменная
окружения `EPKG_SYMLINKS`):

```sh
symlinks = deny   # по умолчанию: пропускать symlink'ы из пакетов
symlinks = keep   # создавать их; при remove они удаляются
```

## Обновление пакетов: upgrade и world-файл

`epkg install` записывает имена явно установленных пакетов в world-файл
`<db>/world` (по одному на строку); `epkg remove` вычёркивает их.
В `epkg list` такие пакеты помечены `[world]`.

```sh
epkg upgrade              # обновить ВСЁ устаревшее из world
epkg upgrade app hello    # обновить (или доустановить) перечисленное;
                          # имена добавляются в world
epkg list                 # app  2.1-r0  ...  [world]
```

Что происходит внутри:

1. для каждого пакета world epkg сравнивает установленную версию с
   версией из индекса (`epk_vercmp`: `1.2.10 > 1.2.9`, `1.0-r1 > 1.0-r0`);
2. строится план через dep-resolution v2 в режиме upgrade: устаревшая
   зависимость не ошибка «version conflict», а автоматическое
   обновление до версии из индекса, в topo-порядке;
3. каждый пакет заменяется атомарно: старые файлы удаляются по
   манифесту БД (включая symlink'и), новые распаковываются с проверкой
   sha256;
4. если ни одного устаревшего нет — `(nothing to do)`.

Транзакция целиком откатываться не умеет (осознанное ограничение), но
каждый шаг идемпотентен: повторный `epkg upgrade` продолжит с места
сбоя.

## Genesis: bootstrap образа ОС (`install --root`)

Сценарий «чистый лист»: вы собираете образ своей ОС на хосте (или в
QEMU с примонтированным диском) и наполняете его пакетами, не имея
работающего epkg внутри образа:

```sh
# 1. конфиг с зеркалом (db/cache указывать НЕ нужно — они поедут в образ)
cat > genesis.conf <<'EOF'
mirror = https://raw.githubusercontent.com/<user>/<repo>/main
EOF

# 2. наполняем чистый образ
epkg --conf genesis.conf install --root /mnt/image base busybox nano

#    структура образа после установки:
#    /mnt/image/usr/bin/...            файлы пакетов
#    /mnt/image/var/lib/epkg/          БД + index.json + world
#    /mnt/image/var/cache/epkg/        скачанные .epkg

# 3. проверяем содержимое образа
epkg --conf genesis.conf list --root /mnt/image

# 4. первая загрузка ОС: epkg уже «из коробки» знает, что установлено,
#    и умеет докачивать оставшиеся пакеты:
#    chroot /mnt/image          # или загрузка ОС в QEMU
#    epkg upgrade
```

Правила `--root`:

* `--root <dir>` меняет и путь распаковки, и расположение БД/кеша:
  они выводятся из корня образа (`<root>/var/lib/epkg`,
  `<root>/var/cache/epkg`), если не заданы явно ключом `--db` /
  `--cachedir`, в `epkg.conf` или через `EPKG_DB` / `EPKG_CACHE`;
* явные `db =` / `cache =` всегда побеждают — можно качать в образ,
  храня кеш на хосте;
* `--conf <file>` задаёт конфиг напрямую (поиск по умолчанию:
  `$EPKG_CONF`, `/etc/epkg.conf`, `./epkg.conf`);
* работает со всеми командами: `install`, `upgrade`, `remove`,
  `list`, `fetch`, `info`, `deps`, `search`.

## Докачка при обрыве

Если соединение оборвалось посреди загрузки пакета, недокачанный файл
остаётся в кеше как `<имя>.part`. Следующая попытка (этим же запуском,
следующим запуском epkg или даже другим зеркалом) посылает
`Range: bytes=<размер>-` и дописывает только недостающее. Финальный
sha256 по индексу гарантирует, что докачанный файл — тот самый. Сервер,
не умеющий Range (ответ 200 вместо 206), просто вызывает повторную
загрузку с нуля.

## Подписи индекса: epkg audit (signify/ed25519)

SHA-256 из индекса защищает канал доставки, но не сам индекс: кто
контролирует зеркало (или DNS/сеть), тот может подменить и индекс,
и пакеты вместе с их хешами. Замыкает цепочку Ed25519-подпись индекса
в формате signify:

```
index.json  --подпись--> index.sig      (делается на стороне мейнтейнера)
epkg.conf:  pubkey = <путь к .pub>      (закрепляется у пользователя)
```

Со стороны мейнтейнера:

```sh
epkg-key gen -c "my hobby os repo 2026" epkg-repo-key
# -> epkg-repo-key (секретный, хранить ОФФЛАЙН) + epkg-repo-key.pub
sh tools/build-sample.sh                      # собрал пакеты + index.json
epkg-key sign -s epkg-repo-key -m index.json -x index.sig
# публикуешь index.json + index.sig + epkg-repo-key.pub одним коммитом
```

Со стороны пользователя (`epkg.conf`):

```
pubkey = /etc/epkg/repo.pub     # путь к файлу...
pubkey = RWS...                 # ...или сам blob (inline base64)
audit  = strict                 # strict (по умолчанию) | warn | off
```

* `epkg update` при заданном `pubkey` скачивает `index.sig` и проверяет
  подпись:
  * `strict` — битый/отсутствующий `index.sig` = зеркало отбрасывается
    целиком (все зеркала без подписи = ошибка update);
  * `warn` — принять с `WARNING: index signature INVALID`;
  * `off` — не проверять (только sha256 пакетов).
* Проверенная подпись кешируется в `<db>/index.sig`.
* `epkg audit` — ручная проверка в любой момент:
  * `epkg audit` — кеш (`<db>/index.json` vs `<db>/index.sig`);
  * `epkg audit --repo <url>` — скачать и проверить зеркало;
  * `epkg audit --file F [--sig S] [--pubkey K]` — произвольный файл;
  * печает отпечаток ключа: `key <keynum>/<pubkey hex>`.
* `epkg-key fp -p key.pub` — отпечаток ключа (сверьте его по доверенному
  каналу один раз, дальше подпись сама защищает от подмены ключа —
  неверный ключ просто не подпишет индекс).

Форматы файлов и модель угроз — в `FORMAT.md`, раздел 5.

## Реальный HTTPS прямо сейчас

```sh
./epkg --help
EPKG_CONF=/dev/null EPKG_DB=/tmp/db EPKG_CACHE=/tmp/cache \
EPKG_CA=ca/roots.pem ./epkg install <имя-пакета-из-твоего-репо>
```

TLS-стек и HTTP-клиент проверены end-to-end против
`raw.githubusercontent.com` (включая следование редиректам с
`github.com/<user>/<repo>/raw/...`).

## Порт на свою ОС

См. **PORTING.md** — пошаговый гайд. Коротко: реализуй
`epk_port_<os>.c` (файлы + память + TCP + энтропия), собери `make`,
положи `epkg.conf` и `ca.pem`.

## Структура

```
include/epk_port.h      контракт порт-слоя (~25 функций)
src/                    ядро: gzip, tar, sha256, ed25519, signify, json,
                        http, tls, deps, движок
src/tls/bearssl/        вендоренный BearSSL (MIT, лицензия внутри)
tools/mkepkg.c          сборщик .epkg из каталога (включая symlink'и)
tools/epkg_key.c        signify-ключи и подписи (gen/sign/verify/fp)
tools/build-sample.sh   генерация примера репозитория (+подпись индекса)
scripts/publish-sample-repo.sh  публикация sample-repo на GitHub
sample-repo/            готовый к пушу GitHub-репозиторий (index.sig + demo.pub)
sample/demo-sec         демо-ключ примера (НЕ используйте для своего репо)
ca/roots.pem            корневые сертификаты (Mozilla CA store)
tests/                  юнит- и e2e-тесты (включая тампер-тесты подписей)
FORMAT.md               спецификация .epkg / index.json / epkg.conf / подписей
PORTING.md              как встроить в свою ОС
```

## Лицензии

Код epkg-tools — MIT. Вендоренный BearSSL — MIT (см.
`src/tls/bearssl/LICENSE.txt`). `ca/roots.pem` — Mozilla CA store
(соответствующая публичная лицензия Mozilla).
