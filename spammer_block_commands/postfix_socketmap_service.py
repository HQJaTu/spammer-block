#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

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
import pwd
import sys
from typing import Optional
from systemd_watchdog import watchdog
import configargparse
import asyncio
import asyncio_glib
import logging
from cysystemd.journal import JournaldLogHandler
from spammer_block_lib import postfix

log = logging.getLogger(__name__)
wd: watchdog = None

DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_SYSTEMD_WATCHDOG_TIME = 5
DEFAULT_LOG_LEVEL = "WARNING"


def _setup_logger(log_level_in: str, watchdog=False) -> None:
    """
    Logging setup
    :param log_level_in:
    :param watchdog:
    :return:
    """
    if watchdog:
        # Running as daemon, Systemd will handle timestamping for us.
        # Also: daemons may have trouble with stdout / stderr, using journald instead.
        handler = JournaldLogHandler()
        log_formatter = logging.Formatter("[%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    else:
        log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(log_formatter)
    handler.propagate = False

    log_level = logging.getLevelName(log_level_in.upper())

    root_logger = logging.getLogger('')
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)


def _systemd_watchdog_keepalive() -> bool:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    wd.notify()

    # The function is called repeatedly until it returns G_SOURCE_REMOVE or FALSE,
    # at which point the timeout is automatically destroyed and the function will not be called again.
    return True


def _systemd_mock_watchdog() -> bool:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    log.debug("Systemd watchdog tick/tock")

    # Keep ticking
    return True


def run_daemon(watchdog_time: int, unix_socket_path: Optional[str], tcp_socket: Optional[tuple[str, int]]) -> None:
    """
    Main loop
    :param watchdog_time:
    :param unix_socket_path:
    :param tcp_socket:
    :return:
    """

    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio_loop = asyncio.new_event_loop()

    # Systemd watchdog?
    if wd.is_enabled:
        # Sets a function to be called at regular intervals with the default priority, G_PRIORITY_DEFAULT.
        # https://docs.gtk.org/glib/func.timeout_add_seconds.html
        log.debug("Systemd Watchdog enabled")
        GLib.timeout_add_seconds(watchdog_time, _systemd_watchdog_keepalive)
        wd.ready()
    else:
        log.info("Systemd Watchdog not enabled")
        # GLib.timeout_add_seconds(watchdog_time, _systemd_mock_watchdog)

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop. PID: {}".format(os.getpid()))

    responder = postfix.PostfixSocketmapResponder(asyncio_loop, unix_socket_path=unix_socket_path, tcp_socket=tcp_socket)
    cancel_event = responder.cancellation_event_factory()
    responder_task = responder.responder_task_factory(cancel_event)

    log.debug("Enter loop")
    asyncio_loop.run_until_complete(responder_task)
    log.debug("Exit loop")
    log.info("Done monitoring for Postfix mapper requests.")


def main() -> None:
    parser = configargparse.ArgumentParser(description='Postfix-mapper Spam Blocker',
                                           default_config_files=['/etc/spammer-block/postfix-socketmap.conf'])
    parser.add_argument('--unix-socket-path',
                        help="Use unix-socket for Postfix IPC.")
    parser.add_argument('--tcp-socket-host',
                        default=DEFAULT_TCP_HOST,
                        help="Use TCP-socket for Postfix IPC, the host.")
    parser.add_argument('--tcp-socket-port',
                        type=int,
                        help="Use TCP-socket for Postfix IPC.")
    parser.add_argument('--watchdog-time', type=int,
                        default=DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--log-level', default=DEFAULT_LOG_LEVEL,
                        help='Set logging level. Python default is: {}'.format(DEFAULT_LOG_LEVEL))
    parser.add_argument("-c", "--config-file",
                        is_config_file=True,
                        help="Specify config file", metavar="FILE")
    args = parser.parse_args()

    _setup_logger(args.log_level)

    # Sanity
    if not args.unix_socket_path and not args.tcp_socket_port:
        raise ValueError("Need either --unix-socket-path or --tcp-socket-host and --tcp-socket-port !")

    # Watchdog
    global wd
    wd = watchdog()

    # Go run the daemon
    log.info('Starting up ...')
    run_daemon(args.watchdog_time,
               args.unix_socket_path,
               (args.tcp_socket_host, args.tcp_socket_port)
               )


if __name__ == "__main__":
    main()
