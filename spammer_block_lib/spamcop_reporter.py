#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import os
import sys
import smtplib
from typing import Union
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import logging

log = logging.getLogger(__name__)


class SpamcopReporter:

    def __init__(self, send_from: str, send_to: Union[str, list], host: str = "127.0.0.1"):
        """
        Send spam report to SpamCop using local SMTPd
        :param send_from: mail sender, mostly irrelevant and not used
        :param send_to: SpamCop reporting address
        :param host: hostname or IP-address to use for sending
        """
        self.send_from = send_from
        if isinstance(send_to, str):
            self.send_to = [send_to]
        elif isinstance(send_to, list):
            self.send_to = send_to
        else:
            input_type = type(send_to)
            raise ValueError("Argument send_to needs to be a string or list! Got: {}".format(input_type))

        self.subject = "Spam report"
        self.mail_server = host

    def report_string(self, message: str, attachment_filename: str) -> None:
        msg = self._create_message()
        part = MIMEApplication(
            message,
            Name=attachment_filename
        )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="{}"'.format(attachment_filename)
        msg.attach(part)

        self._send_message(msg)
        log.debug("Reporting spam from string of length {} characters".format(len(message)))

    def report_stdin(self) -> None:
        message = sys.stdin.read()
        filename = 'spam-mail.txt'

        self.report_string(message, filename)
        log.debug("Reporting spam from stdin")

    def report_files(self, files: list) -> None:
        msg = self._create_message()
        for filename in files:
            if not os.path.exists(filename):
                raise ValueError("File {} does not exist!".format(filename))
            log.debug("Reporting spam from file: {}".format(filename))
            file_basename = os.path.basename(filename)
            with open(filename, "rb") as fil:
                part = MIMEApplication(
                    fil.read(),
                    Name=file_basename
                )
            # After the file is closed
            part['Content-Disposition'] = 'attachment; filename="{}"'.format(file_basename)
            msg.attach(part)

        self._send_message(msg)

    def _create_message(self) -> MIMEMultipart:
        msg = MIMEMultipart()
        msg['From'] = self.send_from
        msg['To'] = COMMASPACE.join(self.send_to)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = self.subject

        msg.attach(MIMEText("Spam report. Body ignored."))

        return msg

    def _send_message(self, msg: MIMEMultipart) -> None:
        smtp = smtplib.SMTP(self.mail_server)
        smtp.sendmail(self.send_from, self.send_to, msg.as_string())
        smtp.close()
