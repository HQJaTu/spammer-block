from .abstract import ReporterAbstract
import logging

log = logging.getLogger(__name__)


class MockReporter(ReporterAbstract):

    def report_string(self, message: str, attachment_filename: str) -> None:
        log.fatal("Spam reporting successfully mocked from string, sending as file: {}".format(attachment_filename))

    def report_files(self, files: list) -> None:
        log.fatal("Spam reporting successfully mocked from files: {}".format(', '.join(files)))
