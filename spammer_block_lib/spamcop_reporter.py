#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import smtplib
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


class SpamcopReporter:

    def __init__(self, send_from, send_to, host="127.0.0.1"):
        self.send_from = send_from
        if isinstance(send_to, str):
            self.send_to = [send_to]
        elif isinstance(send_to, list):
            self.send_to = send_to
        else:
            raise ValueError("Send to needs to be a string or list!")
        self.subject = "Spam report"
        self.mail_server = host

    def _create_message(self):
        msg = MIMEMultipart()
        msg['From'] = self.send_from
        msg['To'] = COMMASPACE.join(self.send_to)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.subject

        msg.attach(MIMEText("Spam report. Body ignored."))

        return msg

    def report_stdin(self):
        msg = self._create_message()
        fil = sys.stdin
        filename = 'spam-mail.txt'
        part = MIMEApplication(
            fil.read(),
            Name=filename
        )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % filename
        msg.attach(part)

        smtp = smtplib.SMTP(self.mail_server)
        smtp.sendmail(self.send_from, self.send_to, msg.as_string())
        smtp.close()

    def report_files(self, files):
        msg = self._create_message()
        for f in files:
            with open(f, "rb") as fil:
                part = MIMEApplication(
                    fil.read(),
                    Name=basename(f)
                )
            # After the file is closed
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
            msg.attach(part)

        smtp = smtplib.SMTP(self.mail_server)
        smtp.sendmail(self.send_from, self.send_to, msg.as_string())
        smtp.close()
