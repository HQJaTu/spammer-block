from .abstract_smtp_reporter import MailReporterAbstract
import logging

log = logging.getLogger(__name__)


class MockReporter(MailReporterAbstract):

    def report_string(self, message: str, attachment_filename: str) -> None:
        msg = self._msg_from_string(message, attachment_filename)
        log.debug("Mock reporter reporting spam from string of length {} characters".format(len(message)))
        self._send_message(msg)

    def report_files(self, files: list) -> None:
        msg = self._msg_from_list_of_files(files)
        for filename in files:
            log.debug("Mock reporter reporting spam from file: {}".format(filename))

        self._send_message(msg)
