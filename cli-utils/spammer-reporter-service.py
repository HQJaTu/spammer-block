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
from systemd.journal import JournaldLogHandler
from spammer_block_lib import dbus, ConfigReader

log = logging.getLogger(__name__)
wd: watchdog = None

BUS_SYSTEM = "system"
BUS_SESSION = "session"

DEFAULT_CONFIG_FILE_NAME = ".spammer-block"


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
    log.handlers.clear()
    log.addHandler(handler)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unkown logging level '{}'!".format(log_level_in))
    log_level = logging._nameToLevel[log_level_in.upper()]
    log.setLevel(log_level)

    lib_log = logging.getLogger('spammer_block_lib')
    lib_log.setLevel(log_level)
    lib_log.handlers.clear()
    lib_log.addHandler(handler)


def gather_mailboxes_to_watch(maildir_base: str, force_root_override: bool, use_sssd: bool) -> list:
    dirs_out = []
    i_am = os.geteuid()
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


def monitor_dbus(use_system_bus: bool, config: dict, use_sssd: bool) -> None:
    watchdog_time = config['Daemon']['watchdog_time']
    maildir_base = config['Daemon']['maildir_base']
    force_root_override = config['Daemon']['force_root_override']

    # DBusGMainLoop(set_as_default=True)
    dbus_loop = DBusGMainLoop()
    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio_loop = asyncio.get_event_loop()

    # Publish the interactive service into D-Bus
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
    parser = argparse.ArgumentParser(description='Spam Email Reporter daemon')
    parser.add_argument('bus_type', metavar='BUS-TYPE-TO-USE', choices=[BUS_SYSTEM, BUS_SESSION],
                        help="D-bus type to use. Choices: {}".format(', '.join([BUS_SYSTEM, BUS_SESSION])))
    parser.add_argument('--from-address', default=ConfigReader.DEFAULT_FROM_ADDRESS,
                        help="Send mail to Spamcop using given sender address. Default: {}".format(
                            ConfigReader.DEFAULT_FROM_ADDRESS))
    parser.add_argument('--smtpd-address', default=ConfigReader.DEFAULT_SMTPD_ADDRESS,
                        help="Send mail using SMTPd at address. Default: {}".format(ConfigReader.DEFAULT_SMTPD_ADDRESS))
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--watchdog-time', type=int,
                        default=ConfigReader.DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(ConfigReader.DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--maildir-base',
                        help="For every user, email is delivered into Maildir. "
                             "Per-user base directory name. Default: none")
    parser.add_argument('--log-level', default=ConfigReader.DEFAULT_LOG_LEVEL,
                        help='Set logging level. Python default is: {}'.format(ConfigReader.DEFAULT_LOG_LEVEL))
    parser.add_argument('--config-file',
                        metavar="TOML-CONFIGURATION-FILE",
                        help="Configuration Toml-file")
    args = parser.parse_args()

    _setup_logger(args.log_level)

    if args.bus_type == BUS_SYSTEM:
        using_system_bus = True
    elif args.bus_type == BUS_SESSION:
        using_system_bus = False
    else:
        raise ValueError("Internal: Which bus?")

    # Read configuration?
    if args.config_file:
        if not os.path.exists(args.config_file):
            log.error("Given configuration file '{}' doesn't exist!".format(args.config_file))
            exit(2)
        log.debug("Reading configuration from: {}".format(args.config_file))
        config = ConfigReader.config_from_toml_file(args.config_file)
    else:
        config = ConfigReader.empty_config()

    # Watchdog
    global wd
    wd = watchdog()

    # Change log-level?
    if wd.is_enabled or (args.log_level == ConfigReader.DEFAULT_LOG_LEVEL and
                         config['Daemon']['log_level'] != ConfigReader.DEFAULT_LOG_LEVEL):
        # --log-level not specified
        # Toml-configuration has log-level specified. Re-do logging setup.
        _setup_logger(config['Daemon']['log_level'], watchdog=wd.is_enabled)

    # Merge CLI-arguments
    if args.from_address != ConfigReader.DEFAULT_FROM_ADDRESS:
        config['Reporter']['from_address'] = args.from_address
    if args.spamcop_report_address:
        config['Reporter']['spamcop_report_address'] = args.spamcop_report_address
    if args.smtpd_address != ConfigReader.DEFAULT_SMTPD_ADDRESS:
        config['Reporter']['smtpd_address'] = args.smtpd_address
    if args.watchdog_time != ConfigReader.DEFAULT_SYSTEMD_WATCHDOG_TIME:
        config['Daemon']['watchdog_time'] = args.watchdog_time
    if args.maildir_base:
        config['Daemon']['maildir_base'] = args.maildir_base

    # Mandatory argument(s) specified?
    if not config['Reporter']['spamcop_report_address'] and not config['Reporter']['mock_report_address']:
        log.error("Need --spamcop-report-address or --mock-report-address (or --config)")
        exit(2)

    # Go run the daemon
    log.info('Starting up ...')
    monitor_dbus(
        using_system_bus,
        config,
        False
    )


if __name__ == "__main__":
    main()
