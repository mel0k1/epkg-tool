# epkg на xv6-riscv

Рабочий порт epkg-tools в xv6-riscv: `epkg update / search / install /
list / fetch` выполняются **внутри эмулируемой ОС**, зеркало epkg-packets
доступно по настоящему TCP/IP через virtio-net + QEMU slirp.

## Что здесь

```
epk_port_xv6.c        порт-слой (include/epk_port.h) на syscall'ах xv6
epk_bigstack_xv6.S    переключатель на выделенный стек (256 КиБ)
epk_tls_stub.c        заглушка TLS (сборка без BearSSL, зеркало по http)
shim/stdio.h          freestanding-заглушка для main.c
kernel/net.c          драйвер virtio-net + стек ARP/IPv4/ICMP/UDP-DNS/TCP
kernel/xv6-net.patch  остальное ядро: lseek, syscall'ы, PLIC, таймер
root/                 epkg.conf + публичные ключи, запекаются в fs.img
```

## Требования к гостевой ОС (что добавлено в xv6)

* virtio-net (modern mmio, slot 1) + минимальный TCP-клиент в ядре;
  фикс. конфиг slirp: ip 10.0.2.15, dns 10.0.2.3. Вызовы:
  `netconnect/netread/netwrite/netclose/netresolve`.
* `lseek` (в ванильном xv6 его нет).
* Плата за простоту: один незавершённый сегмент с ретрансмитом,
  in-order RX. HTTP-зеркалу этого достаточно.

## Ограничения xv6 (не epkg)

* файл на fs ≤ 268 КиБ (нет двойной индirection) — большие пакеты
  не сохранятся в кеш;
* имя файла ≤ 14 символов (dirent) — длинные имена из индекса
  (например `xz-static-5.6.3-r0.epkg`) коллидируют с `.part`;
* symlinks нет — порт всегда возвращает -1 (policy `deny`).

## Как собрать и прогнать

```sh
# 1. ядро: применить kernel/xv6-net.patch, добавить kernel/net.c
# 2. xv6 Makefile: правило $U/_epkg (см. kernel/xv6-net.patch) и UPROGS
# 3. хост: поднять зеркало из epkg-packets
python3 -m http.server 8000 --bind 127.0.0.1   # в каталоге epkg-packets
# 4. собрать образ и ОС
make fs.img && make
# 5. qemu (важно: force-legacy=false — xv6 ждёт virtio v2)
qemu-system-riscv64 -machine virt -bios none -nographic -m 128M \
  -global virtio-mmio.force-legacy=false \
  -kernel kernel/kernel \
  -drive file=fs.img,if=none,format=raw,id=x0 \
  -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
  -netdev user,id=n0 \
  -device virtio-net-device,netdev=n0,bus=virtio-mmio-bus.1
# 6. в консоли xv6:
epkg update          # скачает index.json + index.sig, проверит ed25519
epkg search static
epkg install bar     # подтянет зависимость foo
epkg list
```

## Замечания для портирующих

* `epk_bigstack_run` использует статический буфер BSS (256 КиБ) и
  не возвращается: xv6 без C-рантайма, возврат из `main` = мусор.
  Трамплин завершает процесс через `SYS_exit` с кодом `epkg_main`.
* `epk_rename` — copy+unlink (в xv6 нет rename(2)).
* Каталоги читаются как файлы (dirent 16 байт, inum 0 = пропуск).
* `epk_time()` = 0 (в xv6 нет RTC): TLS/cert-проверки в этой сборке
  и так отключены, signify-подписи от часов не зависят.
