import os
import sys
import requests
from .abstract import ReporterAbstract
import logging

log = logging.getLogger(__name__)


class GmailReporter(ReporterAbstract):
    ABUSE_URL = r"https://support.google.com/mail/contact/abuse"

    def __init__(self):
        # RFC 2047 decoder for mail subject
        pass

    def report_string(self, message: str, attachment_filename: str) -> None:
        pass

    def report_stdin(self) -> None:
        message = sys.stdin.read()

    def report_files(self, files: list) -> None:
        for filename in files:
            if not os.path.exists(filename):
                raise ValueError("File {} does not exist!".format(filename))
            log.debug("Gmail reporter reporting spam from file: {}".format(filename))
            file_basename = os.path.basename(filename)
            with open(filename, "rb") as fil:
                fil.read(),
