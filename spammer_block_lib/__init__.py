# SPDX-License-Identifier: GPL-2.0

from .spammer_block import SpammerBlock
from .output import NetworkOutputNone, NetworkOutputJson, NetworkOutputPostfix

NET_LIST_OUTPUT_OPTIONS = {
    'none': NetworkOutputNone,
    'json': NetworkOutputJson,
    'postfix': NetworkOutputPostfix
}

__all__ = ['SpammerBlock', 'NetworkOutputNone', 'NetworkOutputJson', 'NetworkOutputPostfix',
           'NET_LIST_OUTPUT_OPTIONS']
