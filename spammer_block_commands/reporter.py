#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

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
import argparse
import logging
from spammer_block_lib import ConfigReader, reporter as spam_reporters

log = logging.getLogger(__name__)

DEFAULT_FROM_ADDRESS = "joe.user@example.com"
DEFAULT_SMTPD_ADDRESS = "127.0.0.1"
SPAM_REPORTER_SERVICE_BUS_NAME = "fi.hqcodeshop.SpamReporter"

BUS_SYSTEM = "system"
BUS_SESSION = "session"


def _setup_logger(log_level_in: str) -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.handlers.clear()
    log.addHandler(console_handler)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unkown logging level '{}'!".format(log_level_in))
    log_level = logging._nameToLevel[log_level_in.upper()]
    log.setLevel(log_level)

    lib_log = logging.getLogger('spammer_block_lib')
    lib_log.setLevel(log_level)
    lib_log.handlers.clear()
    lib_log.addHandler(console_handler)


def dbus_reporter(use_system_bus: bool, filename: str) -> None:
    from dbus import (SessionBus, SystemBus, Interface)

    if use_system_bus:
        # Global, system wide
        bus = SystemBus()
        log.debug("Using SystemBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))
    else:
        # User's own
        bus = SessionBus()
        log.debug("Using SessionBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))

    # get the object
    SPAM_REPORTER_SERVICE = SPAM_REPORTER_SERVICE_BUS_NAME.split('.')
    OPATH = "/" + "/".join(SPAM_REPORTER_SERVICE)

    proxy = bus.get_object(SPAM_REPORTER_SERVICE_BUS_NAME, OPATH)
    iface = Interface(proxy, dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME)

    if False:
        # Ping test:
        # call the methods and print the results
        log.info("Sending Ping into D-Bus {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))
        reply = iface.Ping()
        log.info("Response: {}".format(reply))

        return
    if False:
        # Ping test:
        ping_method = proxy.get_dbus_method('Ping', SPAM_REPORTER_SERVICE_BUS_NAME)

        # call the methods and print the results
        log.info("Sending Ping into D-Bus {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))
        reply = ping_method()
        log.info("Response: {}".format(reply))

        return

    # Report spam
    log.debug("Sending ReportFile({}) into D-Bus {} by manual request".format(filename, SPAM_REPORTER_SERVICE_BUS_NAME))
    reply = iface.ReportFile(filename)
    log.debug("Response: {}".format(reply))


def main():
    parser = argparse.ArgumentParser(description='Report received email as spam')
    parser.add_argument('--from-address', default=DEFAULT_FROM_ADDRESS,
                        help="Send mail to Spamcop using given sender address. Default: {}".format(
                            DEFAULT_FROM_ADDRESS))
    parser.add_argument('--smtpd-address', default=DEFAULT_SMTPD_ADDRESS,
                        help="Send mail using SMTPd at address. Default: {}".format(DEFAULT_SMTPD_ADDRESS))
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--mock-report-address', metavar="REPORT-ADDRESS",
                        help="Report to given e-mail address. Simulate reporting for test purposes.")
    parser.add_argument('--report-from-stdin', action="store_true",
                        help="Read email from STDIN and report it as spam")
    parser.add_argument('--report-from-file', metavar="FILENAME",
                        help="Read email from a RFC2822 file and report it as spam")
    parser.add_argument('--dbus', metavar='BUS-TYPE-TO-USE', choices=[BUS_SYSTEM, BUS_SESSION],
                        help="Use D-Bus for reporting. Ignoring all arguments, "
                             "except must use --report-from-file. Choices: {}".format(
                            ', '.join([BUS_SYSTEM, BUS_SESSION])))
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    parser.add_argument('--config-file',
                        metavar="TOML-CONFIGURATION-FILE",
                        help="Configuration Toml-file")
    args = parser.parse_args()
    _setup_logger(args.log_level)

    # Read configuration?
    if args.config_file:
        if not os.path.exists(args.config_file):
            log.error("Given configuration file '{}' doesn't exist!".format(args.config_file))
            exit(2)
        log.debug("Reading configuration from: {}".format(args.config_file))
        config = ConfigReader.config_from_toml_file(args.config_file)
    else:
        config = ConfigReader.empty_config()

    # Change log-level?
    if (args.log_level == ConfigReader.DEFAULT_LOG_LEVEL and
            config['Daemon']['log_level'] != ConfigReader.DEFAULT_LOG_LEVEL):
        # --log-level not specified
        # Toml-configuration has log-level specified. Re-do logging setup.
        _setup_logger(config['Daemon']['log_level'])

    if args.dbus:
        if args.dbus == BUS_SYSTEM:
            using_system_bus = True
        elif args.dbus == BUS_SESSION:
            using_system_bus = False
        else:
            raise ValueError("Internal: Which bus?")

        # Spamcop-stuff
        if not args.report_from_file:
            log.warning("D-Bus must use --report-from-file")
            exit(1)
        if not os.path.exists(args.report_from_file):
            log.error("File {} doesn't exist!".format(args.report_from_file))
            exit(1)
        dbus_reporter(using_system_bus, args.report_from_file)
    else:
        if not args.report_from_stdin and not args.report_from_file:
            log.warning("No arguments given. Printing help.")
            parser.print_help()
            exit(1)

        # Merge CLI-arguments
        if args.from_address != ConfigReader.DEFAULT_FROM_ADDRESS:
            config['Reporter']['from_address'] = args.from_address
        if args.spamcop_report_address:
            config['Reporter']['spamcop_report_address'] = args.spamcop_report_address
        if args.smtpd_address != ConfigReader.DEFAULT_SMTPD_ADDRESS:
            config['Reporter']['smtpd_address'] = args.smtpd_address

        # Mandatory argument(s) specified?
        if config['Reporter']['spamcop_report_address']:
            reporter = spam_reporters.SpamcopReporter(send_from=config['Reporter']['from_address'],
                                                      send_to=config['Reporter']['spamcop_report_address'],
                                                      host=config['Reporter']['smtpd_address'])
        elif config['Reporter']['mock_report_address']:
            reporter = spam_reporters.MockReporter(send_from=config['Reporter']['from_address'],
                                                   send_to=config['Reporter']['mock_report_address'],
                                                   host=config['Reporter']['smtpd_address'])
        else:
            log.error("Need --spamcop-report-address or --mock-report-address (or --config)")
            exit(2)

        if args.report_from_stdin:
            log.info("Reporting from STDIN pipe")
            try:
                reporter.report_stdin()
            except Exception:
                log.exception("Reporting failed!")
        elif args.report_from_file:
            log.info("Reporting file: {}".format(args.report_from_file))
            if not os.path.exists(args.report_from_file):
                log.error("File {} doesn't exist!".format(args.report_from_file))
                exit(1)
            try:
                reporter.report_files([args.report_from_file])
            except Exception:
                log.exception("Reporting failed!")
        else:
            raise NotImplementedError("What? Internal logic failure.")

    log.info("Done spam reporting")
    exit(0)


if __name__ == "__main__":
    main()
