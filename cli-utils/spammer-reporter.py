#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# This file is part of Spamer Block tool.
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


import sys
import argparse
import logging
from spammer_block_lib import *

log = logging.getLogger(__name__)


def _setup_logger():
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)
    log.setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(description='Report received email as spam')
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--spamcop-report-from-stdin', action="store_true",
                        help="Read email from STDIN and report it as spam into Spamcop")
    parser.add_argument('--spamcop-report-from-file', metavar="FILENAME",
                        help="Read email from a RFC2822 file and report it as spam into Spamcop")
    args = parser.parse_args()
    _setup_logger()

    # Spamcop-stuff
    if args.spamcop_report_from_stdin or args.spamcop_report_from_file:
        if not args.spamcop_report_address:
            raise ValueError("Need --spamcop-report-address !")
        log.info("SpamCop reporting")
        reporter = SpamcopReporter(send_from="joe.user@example.com", send_to=args.spamcop_report_address)
        try:
            if args.spamcop_report_from_stdin:
                log.info("Reporting from STDIN pipe")
                reporter.report_stdin()
            elif args.spamcop_report_from_file:
                log.info("Reporting file: %s" % args.spamcop_report_from_file)
                reporter.report_files([args.spamcop_report_from_file])
        except Exception as exc:
            log.error("Reporting failed! Exception: %s" % exc)
        log.info("Done SpamCop reporting")
        exit(0)

    log.warning("No arguments given. Printing help.")
    parser.print_help()
    exit(1)


if __name__ == "__main__":
    main()
