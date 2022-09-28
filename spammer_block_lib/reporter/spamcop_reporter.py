#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
from typing import Union
from .abstract_smtp_reporter import MailReporterAbstract
import logging

log = logging.getLogger(__name__)


class SpamcopReporter(MailReporterAbstract):

    def __init__(self, send_from: str, send_to: Union[str, list], host: str):
        super().__init__(send_from, send_to, host)
        """
        Send spam report to SpamCop using local SMTPd
        :param send_from: mail sender, mostly irrelevant and not used
        :param send_to: SpamCop reporting address
        :param host: hostname or IP-address to use for sending
        """
        pass

    def report_string(self, message: str, attachment_filename: str) -> None:
        msg = self._msg_from_string(message, attachment_filename)
        log.debug("SpamCop reporter reporting spam from string of length {} characters".format(len(message)))
        self._send_message(msg)

    def report_stdin(self) -> None:
        message = sys.stdin.read()
        filename = 'spam-mail.txt'

        self.report_string(message, filename)
        log.debug("SpamCop reporter reporting spam from stdin")

    def report_files(self, files: list) -> None:
        msg = self._msg_from_list_of_files(files)
        for filename in files:
            log.debug("SpamCop reporter reporting spam from file: {}".format(filename))

        self._send_message(msg)
