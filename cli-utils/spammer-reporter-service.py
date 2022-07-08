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
from systemd_watchdog import watchdog
from typing import Optional, Tuple
import argparse
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
import asyncio
import asyncio_glib
import re
import logging
from spammer_block_lib import dbus

log = logging.getLogger(__name__)
wd: watchdog = None

BUS_SYSTEM = "system"
BUS_SESSION = "session"

DEFAULT_SYSTEMD_WATCHDOG_TIME = 5
DEFAULT_FROM_ADDRESS = "joe.user@example.com"
DEFAULT_SMTPD_ADDRESS = "127.0.0.1"
DEFAULT_CONFIG_FILE_NAME = ".spammer-block"


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


def gather_mailboxes_to_watch(maildir_base: str, use_sssd: bool) -> list:
    dirs_out = []
    i_am = os.geteuid()
    if i_am == 0:
        users_to_check = []
        if use_sssd:
            # If SSSd doesn't roll all the users over, but has enumerate = True in config
            # use a bigger hammer to get the list of users.
            from spammer_block_lib.dbus import sssd
            user_getter = sssd.Sssd()
            for uid in user_getter.users():
                users_to_check.append(uid)
        else:
            # Use standard method for listing all users.
            for user in pwd.getpwall():
                users_to_check.append(user[2])
    else:
        users_to_check = [i_am]
    for uid in users_to_check:
        user, users_watchlist = _check_for_config_file(maildir_base, uid)
        if users_watchlist:
            log.info("Found directories to watch for user ID {} ({})".format(uid, user))
            dirs_out.extend(users_watchlist)

    return dirs_out


def _check_for_config_file(maildir_base: str, uid: int) -> Tuple[Optional[str], Optional[list]]:
    pw_data = pwd.getpwuid(uid)
    if not pw_data:
        return None, None
    home_dir = pw_data[5]
    linux_usr = pw_data[0]
    if not os.path.exists(home_dir):
        return linux_usr, None

    config_file = "{}/{}".format(home_dir, DEFAULT_CONFIG_FILE_NAME)
    if not os.path.exists(config_file):
        return linux_usr, None

    dirs_out = []
    with open(config_file, "rt", encoding="utf-8") as config:
        for line in config:
            trimmed_line = line.strip()
            if not trimmed_line:
                # Skip empty line
                continue
            if re.match(r"^#", trimmed_line):
                # Skip comment
                continue

            maildir_name = trimmed_line.replace('/', '.')

            # Maildir works with mail arriving at new/, transferring into cur/ when MUA sees it.
            # 1) Watch new/ as it will see the mail first before MUA moves it to cur/.
            # 2) Any already received mail will be in cur/ and when moved to another folder will stay in cur/.
            # Need to watch them both!
            parts = ['new', 'cur']
            for part in parts:
                if maildir_base:
                    physical_dir = "{}/{}/.{}/{}/".format(home_dir, maildir_base, maildir_name, part)
                else:
                    physical_dir = "{}/.{}/{}/".format(home_dir, maildir_name, part)

                if not os.path.exists(physical_dir):
                    log.warning("User ID {} has Maildir '{}' in {}. It doesn't exist! "
                                "Skipping.".format(uid, trimmed_line, DEFAULT_CONFIG_FILE_NAME))
                    continue
                if not os.path.isdir(physical_dir):
                    log.warning("User ID {} has Maildir '{}' in {}. It's a file at: {} "
                                "Skipping.".format(uid, trimmed_line, physical_dir, DEFAULT_CONFIG_FILE_NAME))
                    continue
                dirs_out.append(physical_dir)

    return linux_usr, dirs_out


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


def monitor_dbus(use_system_bus: bool, watchdog_time: int,
                 send_from: str, send_to: str, smtpd_host: str,
                 maildir_base: str, use_sssd: bool) -> None:
    wd = watchdog()

    # DBusGMainLoop(set_as_default=True)
    dbus_loop = DBusGMainLoop()
    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio_loop = asyncio.get_event_loop()

    # Publish the interactive service into D-Bus
    dbus.SpamReporterService(
        use_system_bus,
        send_from, send_to, dbus_loop, smtpd_host
    )

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

    # Dirs to watch
    dirs = gather_mailboxes_to_watch(maildir_base, use_sssd)
    inode_watcher = dbus.FolderWatcher(asyncio_loop, use_system_bus, do_report=True)
    cancel_event = inode_watcher.cancellation_event_factory()
    inode_watcher_task = inode_watcher.watcher_task_factory(cancel_event, dirs)

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop. PID: {}".format(os.getpid()))

    log.debug("Enter loop")
    asyncio_loop.run_until_complete(inode_watcher_task)
    log.debug("Exit loop")
    log.info("Done monitoring for outgoing spam.")


def main() -> None:
    parser = argparse.ArgumentParser(description='Spam Email Reporter daemon')
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
    parser.add_argument('--maildir-base',
                        help="For every user, email is delivered into Maildir. "
                             "Per-user base directory name. Default: none")
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
        args.smtpd_address,
        args.maildir_base,
        False
    )


if __name__ == "__main__":
    main()
