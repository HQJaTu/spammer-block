# SPDX-License-Identifier: GPL-2.0

"""
Shared logging setup for the systemd daemons (reporter_service,
postfix_socketmap_service).

The timestamp decision hinges on whether systemd/journald is capturing our
output: when the daemon is started by systemd as a notify service the journal
already timestamps every entry, so emitting our own timestamp would duplicate
it. The caller passes ``watchdog=wd.is_enabled`` (i.e. NOTIFY_SOCKET present);
this must be determined *before* logging is configured, so the very first log
line already has the correct format.
"""

import logging
import sys

from cysystemd.journal import JournaldLogHandler


def setup_logger(log_level_in: str, watchdog: bool = False) -> None:
    """
    Configure root logging for a daemon.

    :param log_level_in: log level name, e.g. "INFO".
    :param watchdog: True when started by systemd (NOTIFY_SOCKET present). Then
                     records go straight to the journal with no in-message
                     timestamp (journald timestamps them). When False (manual
                     run), a timestamped stderr handler is used.
    """
    if watchdog:
        # systemd/journald timestamps for us; daemons may also have unreliable
        # stdout/stderr, so log straight to the journal.
        handler = JournaldLogHandler()
        log_formatter = logging.Formatter(
            "[%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    else:
        handler = logging.StreamHandler(sys.stderr)
        log_formatter = logging.Formatter(
            "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    handler.setFormatter(log_formatter)

    log_level = logging.getLevelName(log_level_in.upper())

    # Attach the handler to the root logger only. Every logger (including
    # 'spammer_block_lib' and its children) propagates its records up to the
    # root, so a single handler here emits each record exactly once. Adding the
    # same handler to both root and 'spammer_block_lib' would emit library
    # records twice (once by the child handler, once after propagation to root).
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Ensure the library logger has no stray handlers and propagates to root.
    lib_logger = logging.getLogger('spammer_block_lib')
    lib_logger.handlers.clear()
    lib_logger.propagate = True
