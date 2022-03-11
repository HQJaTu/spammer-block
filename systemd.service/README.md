# Spam reporter service
Systemd service for reporting received email as spam

## Test send email
When service is running, see if D-Bus works.

```bash
dbus-send \
  --session \
  --print-reply \
  --type=method_call \
  --dest=com.spamcop.Reporter \
  /com/spamcop/Reporter com.spamcop.Reporter.Ping
```

## Test send email
When service is running, following command will report file named `-FILENAME-HERE-` as spam.

```bash
dbus-send \
  --session \
  --print-reply \
  --type=method_call \
  --dest=com.spamcop.Reporter \
  /com/spamcop/Reporter com.spamcop.Reporter.ReportFile "string:-FILENAME-HERE-"
```
