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
import argparse
from pydbus import SystemBus, SessionBus
from gi.repository import GLib
import asyncio
from asyncinotify import Inotify, Mask
import gbulb
import logging
from spammer_block_lib import dbus

log = logging.getLogger(__name__)
wd = None

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


async def dir_watcher():
    """
    Docs: https://asyncinotify.readthedocs.io/en/latest/
    Example:
     Inotify event in /tmp/fubar: <Event name=PosixPath('juttu') mask=<Mask.CREATE: 256> cookie=0 watch=<Watch path=PosixPath('/tmp/fubar') mask=<Mask.CREATE|MOVE|MOVED_TO|MOVED_FROM|MODIFY: 450>>>
     Path: PosixPath('/tmp/fubar/juttu')
    :return:
    """
    dir = '/tmp/fubar'

    # Context manager to close the inotify handle after use
    with Inotify() as inotify:
        # Adding the watch can also be done outside of the context manager.
        # __enter__ doesn't actually do anything except return self.
        # This returns an asyncinotify.inotify.Watch instance
        inotify.add_watch(dir, Mask.MODIFY | Mask.CREATE | Mask.MOVE)

        # Iterate events forever, yielding them one at a time
        async for event in inotify:
            # Events have a helpful __repr__.  They also have a reference to
            # their Watch instance.
            log.debug("Inotify event in {}: {}".format(dir, event))

            # the contained path may or may not be valid UTF-8.  See the note
            # below
            log.debug("  Path: {}".format(repr(event.path)))


def monitor_dbus(watchdog_time: int, send_from: str, send_to: str, host: str) -> None:
    wd = systemd_watchdog.watchdog()

    bus = SessionBus()
    # bus = SystemBus()
    bus.publish(
        dbus.SpamReporterService.SPAM_REPORTER_SERVICE_BUS_NAME,
        dbus.SpamReporterService(send_from, send_to, host)
    )

    if wd.is_enabled:
        # Sets a function to be called at regular intervals with the default priority, G_PRIORITY_DEFAULT.
        # https://docs.gtk.org/glib/func.timeout_add_seconds.html
        log.debug("Systemd Watchdog enabled")
        GLib.timeout_add_seconds(watchdog_time, _systemd_watchdog)
        wd.ready()
    else:
        log.info("Systemd Watchdog not enabled")
        GLib.timeout_add_seconds(watchdog_time, _systemd_mock_watchdog)

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop")
    asyncio.set_event_loop_policy(gbulb.GLibEventLoopPolicy())
    loop = asyncio.get_event_loop()
    try:
        # loop.run_forever()
        loop.run_until_complete(dir_watcher())
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
    log.info("Done monitoring for outgoing spam.")


def main():
    parser = argparse.ArgumentParser(description='SpamCop reporter daemon')
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

    log.info('Starting up ...')

    monitor_dbus(
        args.watchdog_time,
        args.from_address,
        args.spamcop_report_address,
        args.smtpd_address
    )


if __name__ == "__main__":
    main()
