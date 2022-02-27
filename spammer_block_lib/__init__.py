# SPDX-License-Identifier: GPL-2.0

from .spammer_block import SpammerBlock
from .outputs import NetworkOutputNone, NetworkOutputJson, NetworkOutputPostfix
from .spamcop_reporter import SpamcopReporter

NET_LIST_OUTPUT_OPTIONS = {
    'none': NetworkOutputNone,
    'json': NetworkOutputJson,
    'postfix': NetworkOutputPostfix
}

__all__ = ['SpammerBlock', 'NetworkOutputNone', 'NetworkOutputJson', 'NetworkOutputPostfix',
           'NET_LIST_OUTPUT_OPTIONS',
           'SpamcopReporter']
