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
import configargparse
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
import asyncio
import asyncio_glib
import re
import logging
from cysystemd.journal import JournaldLogHandler
from spammer_block_lib import dbus

log = logging.getLogger(__name__)
wd: watchdog = None

BUS_SYSTEM = "system"
BUS_SESSION = "session"

DEFAULT_CONFIG_FILE_NAME = ".spammer-block"
DEFAULT_FROM_ADDRESS = "joe.user@example.com"
DEFAULT_SMTPD_ADDRESS = "127.0.0.1"
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


def gather_mailboxes_to_watch(maildir_base: str, force_root_override: bool, use_sssd: bool) -> list:
    dirs_out = []
    i_am = os.geteuid()
    user_watchlist_cnt = 0
    if i_am == 0 or force_root_override:
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
            user_watchlist_cnt += 1
            log.info("Found directories to watch for user ID {} ({})".format(uid, user))
            dirs_out.extend(users_watchlist)

    if dirs_out:
        log.debug("After checking for {} users, found {} users with directories to watch.".format(
            len(users_to_check), user_watchlist_cnt
        ))
    else:
        log.warning("After checking for {} users, didn't find any directories to watch.".format(len(users_to_check)))

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


def monitor_dbus(use_system_bus: bool, watchdog_time: int, maildir_base: str, force_root_override: bool,
                 from_address: str, spamcop_report_address: str, smtpd_address: str, mock_report_address: str,
                 use_sssd: bool) -> None:
    # DBusGMainLoop(set_as_default=True)
    dbus_loop = DBusGMainLoop()
    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio_loop = asyncio.get_event_loop()

    # Publish the interactive service into D-Bus
    config = {
        'Reporter': {
            'from_address': from_address,
            'spamcop_report_address': spamcop_report_address,
            'smtpd_address': smtpd_address,
            'mock_report_address': mock_report_address
        }
    }
    dbus.SpamReporterService(use_system_bus, dbus_loop, config)

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
    dirs = gather_mailboxes_to_watch(maildir_base, force_root_override, use_sssd)
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
    parser = configargparse.ArgumentParser(description='Spam Email Reporter daemon',
                                           default_config_files=['/etc/spammer-block/reporter.conf',
                                                                 '~/.spammer-reporter'])
    parser.add_argument('bus_type', metavar='BUS-TYPE-TO-USE', choices=[BUS_SYSTEM, BUS_SESSION],
                        help="D-bus type to use. Choices: {}".format(', '.join([BUS_SYSTEM, BUS_SESSION])))
    parser.add_argument('--from-address', default=DEFAULT_FROM_ADDRESS,
                        help="Send mail to Spamcop using given sender address. Default: {}".format(
                            DEFAULT_FROM_ADDRESS))
    parser.add_argument('--smtpd-address', default=DEFAULT_SMTPD_ADDRESS,
                        help="Send mail using SMTPd at address. Default: {}".format(DEFAULT_SMTPD_ADDRESS))
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--mock-report-address', metavar="REPORT-ADDRESS",
                        help="Report to given e-mail address. Simulate reporting for test purposes.")
    parser.add_argument('--watchdog-time', type=int,
                        default=DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--maildir-base',
                        help="For every user, email is delivered into Maildir. "
                             "Per-user base directory name. Default: none")
    parser.add_argument('--log-level', default=DEFAULT_LOG_LEVEL,
                        help='Set logging level. Python default is: {}'.format(DEFAULT_LOG_LEVEL))
    parser.add_argument('--force-root-override', action='store_true',
                        help='When launching the daemon, check all users even not running as root '
                             '(may not be allowed).')
    parser.add_argument("-c", "--config-file",
                        is_config_file=True,
                        help="Specify config file", metavar="FILE")
    args = parser.parse_args()

    _setup_logger(args.log_level)

    if args.bus_type == BUS_SYSTEM:
        using_system_bus = True
    elif args.bus_type == BUS_SESSION:
        using_system_bus = False
    else:
        raise ValueError("Internal: Which bus?")

    # Watchdog
    global wd
    wd = watchdog()

    # Mandatory argument(s) specified?
    if not args.spamcop_report_address and not args.mock_report_address:
        log.error("Need --spamcop-report-address or --mock-report-address (or --config)")
        exit(2)

    # Go run the daemon
    log.info('Starting up ...')
    monitor_dbus(
        using_system_bus,
        args.watchdog_time,
        args.maildir_base,
        args.force_root_override,
        args.from_address,
        args.spamcop_report_address,
        args.smtpd_address,
        args.mock_report_address,
        False
    )


if __name__ == "__main__":
    main()
