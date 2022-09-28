import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from .abstract import ReporterAbstract
import logging

log = logging.getLogger(__name__)


class SendgridReporter(ReporterAbstract):
    ABUSE_EMAIL = r"abuse@sendgrid.com"

    def __init__(self, send_from: str, host: str = "127.0.0.1"):
        """
        Send spam report to Sendgrid using local SMTPd
        Docs: https://sendgrid.com/report-spam/
        :param send_from: mail sender, mostly irrelevant and not used
        :param host: hostname or IP-address to use for sending
        """
        self.send_from = send_from
        self.send_to = [self.ABUSE_EMAIL]
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
        log.debug("Sendgrid reporter reporting spam from string of length {} characters".format(len(message)))

    def report_files(self, files: list) -> None:
        raise NotImplementedError("Not yet!")

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
