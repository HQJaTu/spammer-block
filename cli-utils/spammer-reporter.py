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


def main():
    parser = argparse.ArgumentParser(description='Report received email as spam')
    parser.add_argument('--spamcop-report-address', metavar="REPORT-ADDRESS",
                        help="Report to Spamcop using given address")
    parser.add_argument('--spamcop_report_from_stdin', action="store_true",
                        help="Read email from STDIN and report it as spam into Spamcop")
    args = parser.parse_args()

    # Spamcop-stuff
    if args.spamcop_report_from_stdin:
        if not args.spamcop_report_address:
            raise ValueError("Need --spamcop-report-address !")
        reporter = SpamcopReporter(send_from="joe.user@example.com", send_to=args.spamcop_report_address)
        reporter.report_stdin()
        exit(0)

    parser.print_help()
    exit(1)


if __name__ == "__main__":
    main()
