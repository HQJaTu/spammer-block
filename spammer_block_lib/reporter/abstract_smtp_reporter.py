# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# This file is part of Spammer Block library and tool.
# Spamer Block is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia

import os
import smtplib
from typing import Union
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from .abstract import ReporterAbstract
import logging

log = logging.getLogger(__name__)


class MailReporterAbstract(ReporterAbstract):

    def __init__(self, send_from: str, send_to: Union[str, list], host: str):
        """
        Send spam report to SpamCop using local SMTPd
        :param send_from: mail sender, mostly irrelevant and not used
        :param send_to: reporting address
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

    def _msg_from_string(self, message: str, attachment_filename: str) -> MIMEMultipart:
        msg = self._create_message()
        part = MIMEApplication(
            message,
            Name=attachment_filename
        )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="{}"'.format(attachment_filename)
        msg.attach(part)

        return msg

    def _msg_from_list_of_files(self, files: list) -> MIMEMultipart:
        if not files:
            raise ValueError("Cannot create SMTP-message without files!")

        msg = self._create_message()
        for filename in files:
            if not os.path.exists(filename):
                raise ValueError("File {} does not exist!".format(filename))

            file_basename = os.path.basename(filename)
            with open(filename, "rb") as input_file:
                part = MIMEApplication(
                    input_file.read(),
                    Name=file_basename
                )

            # After the file is closed
            part['Content-Disposition'] = 'attachment; filename="{}"'.format(file_basename)
            msg.attach(part)

        return msg

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
