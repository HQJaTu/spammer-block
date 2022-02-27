# SPDX-License-Identifier: GPL-2.0

from .spammer_block import SpammerBlock
from .spammer_reporter import SpammerReporterNone, SpammerReporterJson, SpammerReporterPostfix
from .spamcop_reporter import SpamcopReporter

NET_LIST_OUTPUT_OPTIONS = {
    'none': SpammerReporterNone,
    'json': SpammerReporterJson,
    'postfix': SpammerReporterPostfix
}

__all__ = ['SpammerBlock', 'SpammerReporterNone', 'SpammerReporterJson', 'SpammerReporterPostfix',
           'NET_LIST_OUTPUT_OPTIONS',
           'SpamcopReporter']
