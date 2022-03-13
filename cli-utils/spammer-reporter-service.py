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
import sys
import systemd_watchdog
from typing import Optional, AsyncIterator
import argparse
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
import asyncio
import gbulb
import logging
from spammer_block_lib import dbus

log = logging.getLogger(__name__)
wd = None

BUS_SYSTEM = "system"
BUS_SESSION = "session"

DEFAULT_SYSTEMD_WATCHDOG_TIME = 5
DEFAULT_FROM_ADDRESS = "joe.user@example.com"
DEFAULT_SMTPD_ADDRESS = "127.0.0.1"


def _setup_logger(log_level_in: str) -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unkown logging level '{}'!".format(log_level_in))
    log_level = logging._nameToLevel[log_level_in.upper()]
    log.setLevel(log_level)

    lib_log = logging.getLogger('spammer_block_lib')
    lib_log.setLevel(log_level)
    lib_log.addHandler(console_handler)


def _systemd_watchdog() -> bool:
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


def monitor_dbus(use_system_bus: bool, watchdog_time: int,
                 send_from: str, send_to: str, smtpd_host: str) -> None:
    wd = systemd_watchdog.watchdog()

    # DBusGMainLoop(set_as_default=True)
    dbus_loop = DBusGMainLoop()
    gbulb.install(gtk=False)
    asyncio.set_event_loop_policy(gbulb.GLibEventLoopPolicy())
    loop = asyncio.get_event_loop()

    # Publish the service into D-Bus
    dbus.SpamReporterService(
        use_system_bus,
        send_from, send_to, dbus_loop, smtpd_host
    )

    if wd.is_enabled:
        # Sets a function to be called at regular intervals with the default priority, G_PRIORITY_DEFAULT.
        # https://docs.gtk.org/glib/func.timeout_add_seconds.html
        log.debug("Systemd Watchdog enabled")
        GLib.timeout_add_seconds(watchdog_time, _systemd_watchdog)
        wd.ready()
    else:
        log.info("Systemd Watchdog not enabled")
        # GLib.timeout_add_seconds(watchdog_time, _systemd_mock_watchdog)

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop. PID: {}".format(os.getpid()))
    ino = dbus.FolderWatcher()
    task = loop.create_task(ino.dir_watcher())

    try:
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        # Avoid "Task was destroyed but it is pending!" -error
        # GLib task doesn't need cancelling.
        task.cancel()
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        ino.close()
        loop.close()
    log.info("Done monitoring for outgoing spam.")


def main() -> None:
    parser = argparse.ArgumentParser(description='SpamCop reporter daemon')
    parser.add_argument('bus_type', metavar='BUS-TYPE-TO-USE', choices=[BUS_SYSTEM, BUS_SESSION],
                        help="D-bus type to use. Choices: {}".format(', '.join([BUS_SYSTEM, BUS_SESSION])))
    parser.add_argument('--from-address', default=DEFAULT_FROM_ADDRESS,
                        help="Send mail to Spamcop using given sender address. Default: {}".format(
                            DEFAULT_FROM_ADDRESS))
    parser.add_argument('--smtpd-address', default=DEFAULT_SMTPD_ADDRESS,
                        help="Send mail using SMTPd at address. Default: {}".format(DEFAULT_SMTPD_ADDRESS))
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--watchdog-time', type=int,
                        default=DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    args = parser.parse_args()

    _setup_logger(args.log_level)
    if not args.spamcop_report_address:
        log.error("Need --spamcop-report-address")
        exit(2)

    if args.bus_type == BUS_SYSTEM:
        using_system_bus = True
    elif args.bus_type == BUS_SESSION:
        using_system_bus = False
    else:
        raise ValueError("Internal: Which bus?")

    log.info('Starting up ...')

    monitor_dbus(
        using_system_bus,
        args.watchdog_time,
        args.from_address,
        args.spamcop_report_address,
        args.smtpd_address
    )


if __name__ == "__main__":
    main()
