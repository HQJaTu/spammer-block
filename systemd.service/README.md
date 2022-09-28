# Spam reporter service
Systemd service for reporting received email as spam

# D-Bus

## Bus-types
For docs, see: https://dbus.freedesktop.org/doc/dbus-python/tutorial.html#connecting-to-the-bus

* Per user _SessionBus_, `dbus-send --session`
* Global _SystemBus_, `dbus-send --system`

Note: On a request, default is `--session`.

## Install into `--system`
Policy install (as _root_):
1. Copy file `spamreporter-dbus.conf` into directory `/etc/dbus-1/system.d/`
2. Make policy change effective: `systemctl reload dbus`
3. List available services:
    ```bash
    dbus-send \
      --system \
      --print-reply \
      --type=method_call \
      --dest=org.freedesktop.DBus \
      /org/freedesktop/DBus org.freedesktop.DBus.ListNames
    ```
   Response will contain published interface:
    ```text
    method return time=123.456 sender=org.freedesktop.DBus -> destination=:1.1234 serial=3 reply_serial=2
    array [
      string "org.freedesktop.DBus"
      string "fi.hqcodeshop.SpamReporter"
      ...
    ]
    ```
4. Verify published service details:
    ```bash
    busctl introspect fi.hqcodeshop.SpamReporter /fi/hqcodeshop/SpamReporter fi.hqcodeshop.SpamReporter
    ```
   Response will contain published interface:
    ```text
    NAME                 TYPE      SIGNATURE RESULT/VALUE FLAGS
    .Ping                method    -         s            -
    .ReportFile          method    s         s            -
    ```
5. Test service with a ping:
    ```bash
    dbus-send --print-reply \
      --system \
      --type=method_call \
      --dest=fi.hqcodeshop.SpamReporter \
      /fi/hqcodeshop/SpamReporter fi.hqcodeshop.SpamReporter.Ping
    ```
   Response will contain a greeting to the caller:
    ```text
    method return time=1647618215.603226 sender=:1.250 -> destination=:1.252 serial=6 reply_serial=2
       string "Hi Joe User in system-bus! pong"
    ```
6. Done!

## Test ping `--session`
When service is running, see if D-Bus works.

Run:
```bash
dbus-send \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.SpamReporter \
  /fi/hqcodeshop/SpamReporter fi.hqcodeshop.SpamReporter.Ping
```

Response (based on user who sent the ping):
```text
   string "Hi Joe Nobody! pong"
```

## Test send email `--system`
When service is running, following command will report file named `-FILENAME-HERE-` as spam.

```bash
dbus-send \
  --system \
  --print-reply \
  --type=method_call \
  --dest=--dest=fi.hqcodeshop.SpamReporter \
  /fi/hqcodeshop/SpamReporter fi.hqcodeshop.SpamReporter.ReportFile "string:-FILENAME-HERE-"
```

# Systemd

## Capabilities
`.service` definition has following:

    CapabilityBoundingSet=CAP_AUDIT_WRITE CAP_DAC_READ_SEARCH CAP_IPC_LOCK CAP_SYS_NICE

`man 7 capabilities` @ https://man7.org/linux/man-pages/man7/capabilities.7.html

* **CAP_AUDIT_WRITE** (since Linux 2.6.11)
  * Write records to kernel auditing log.
* **CAP_DAC_READ_SEARCH**
  * Bypass file read permission checks and directory read and execute permission checks;
  * invoke open_by_handle_at(2);
  * use the linkat(2) AT_EMPTY_PATH flag to create a link to a file referred to by a file descriptor.
* **CAP_IPC_LOCK**
  * Lock memory (mlock(2), mlockall(2), mmap(2), shmctl(2));
  * Allocate memory using huge pages (memfd_create(2), mmap(2), shmctl(2)).
* **CAP_SYS_NICE**
  * Lower the process nice value (nice(2), setpriority(2)) and change the nice value for arbitrary processes;
  * set real-time scheduling policies for calling process, and set scheduling policies and priorities for arbitrary processes (sched_setscheduler(2), sched_setparam(2), sched_setattr(2));
  * set CPU affinity for arbitrary processes (sched_setaffinity(2));
  * set I/O scheduling class and priority for arbitrary processes (ioprio_set(2));
  * apply migrate_pages(2) to arbitrary processes and allow processes to be migrated to arbitrary nodes;
  * apply move_pages(2) to arbitrary processes;
  * use the MPOL_MF_MOVE_ALL flag with mbind(2) and move_pages(2).

## UID / GID of the service
Service is run as _root_.

When running as non-_root_, capability _CAP_DAC_READ_SEARCH_ does allow reading of other users' files,
but doesn't allow traversing directories or querying for file existence. Thus, basic operation of this
daemon is unavailable.

For security reasons, it would be sensible for daemon to run as non-_root_, however, there doesn't seem to be suitable
capability to allow iterating directory contents or traversing filesystem while ignoring
permissions. Such functionality is critical, feasible options for non-_root_ operation are lacking, so daemon runs as _root_.

## Checking effective capabilities of the service

1. Find PID, `systemctl status spammer-reporter`
2. Run command: `gawk '/^CapEff/ {print $2}' /proc/<PID-OF-PROCESS>/status | xargs -n1 -I {} capsh --decode={}`
3. Expected output: `0x0000000020804004=cap_dac_read_search,cap_ipc_lock,cap_sys_nice,cap_audit_write`

Note:
See man-page for definitions of:
_Permitted_, _Inheritable_, _Effective_, _Bounding_ and _Ambient_ capability sets.

# SElinux

See subdirectory `SElinux/` for details.

## Test run service

* Use SElinux-tool `runcon`. Set _system_u:system_r:spammerblock_t:s0_ as security context.

```bash
runcon system_u:system_r:spammerblock_t:s0 \
  /usr/libexec/spammer-block/bin/python \
  /usr/libexec/spammer-block/bin/spammer-reporter-service.py \
  system \
  --config /etc/sysconfig/spammer-reporter.toml
```

* [runcon(1) - Linux man page](https://linux.die.net/man/1/runcon)

## Temporarily disable all don't audit -rules

```bash
semodule -DB
```

Now all possible deny-rules are logged and can be traced with `audit2allow`.
