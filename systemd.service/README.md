# Spam reporter service
Systemd service for reporting received email as spam

## Bus-types
For docs, see: https://dbus.freedesktop.org/doc/dbus-python/tutorial.html#connecting-to-the-bus

* Per user _SessionBus_, `dbus-send --session`
* Global _SystemBus_, `dbus-send --system`

Note: On a request, default is `--session`.

## Install into `--system`
Policy install (as _root_):
1. Copy file `spamreporter-dbus.conf` into directory `/etc/dbus-1/system.d/`
2. Make policy change effective: `systemctl reload dbus`
3. Verify service is published:
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
      string "com.spamcop.Reporter"
      ...
   ]
    ```
5. Done!

## Test ping `--session`
When service is running, see if D-Bus works.

Run:
```bash
dbus-send \
  --print-reply \
  --type=method_call \
  --dest=com.spamcop.Reporter \
  /com/spamcop/Reporter com.spamcop.Reporter.Ping
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
  --dest=com.spamcop.Reporter \
  /com/spamcop/Reporter com.spamcop.Reporter.ReportFile "string:-FILENAME-HERE-"
```
