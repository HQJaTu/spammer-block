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
from spammer_block_lib import datasources

log = logging.getLogger(__name__)


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

    whois_log = logging.getLogger('ipwhois')
    spammer_log = logging.getLogger('spammer_block_lib')
    whois_log.setLevel(log_level)
    whois_log.addHandler(console_handler)
    spammer_log.setLevel(log_level)
    spammer_log.addHandler(console_handler)


def main():
    parser = argparse.ArgumentParser(description='Block IP-ranges of a spammer',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('ip', metavar="IP",
                        help='IPv4 address to query for')
    parser.add_argument('--asn', '-a',
                        help='Skip querying for ASN')
    parser.add_argument('--skip-overlapping', action="store_true",
                        default=True,
                        help="Don't display any overlapping subnets. Default: yes")
    parser.add_argument('--output-format', '-o', default='postfix',
                        help='Output format. Choices: ' +
                             ', '.join(NET_LIST_OUTPUT_OPTIONS) + "\n" +
                             'Default: "postfix" will produce Postfix CIDR-table')
    parser.add_argument('--output-file',
                        help='Output to a file.')
    parser.add_argument('--postfix-rule', default=SpammerReporterPostfix.DEFAULT_POSTFIX_RULE,
                        help='CIDR-table rule to apply for a net.\n'
                             'Dynamic AS-number assignment with "{{ASN}}".\n'
                             'Default: "{}"'.format(
                            SpammerReporterPostfix.DEFAULT_POSTFIX_RULE)
                        )
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    parser.add_argument('--ipinfo-token', default=None,
                        help='ipinfo.io API access token if using paid ASN query service')
    parser.add_argument('--asn-result-json-file',
                        help='To conserve ASN-queries, save query result\n'
                             'or use existing result from a previous query.')
    args = parser.parse_args()

    _setup_logger(args.log_level)

    # Select datasource
    # ds = datasources.RADb(args.ip)
    ds = datasources.IPInfoIO_UI()
    # ds = datasources.IPInfoIO(args.ip, token=args.ipinfo_token)

    # Go process
    spammer_blocker = SpammerBlock(ds)
    asn, nets_for_as = spammer_blocker.whois_query(args.ip,
                                                   asn=args.asn,
                                                   asn_json_result_file=args.asn_result_json_file)

    # Go output
    output_formatter_class = NET_LIST_OUTPUT_OPTIONS.get(args.output_format, SpammerReporterNone)
    output_formatter = output_formatter_class()
    if isinstance(output_formatter, SpammerReporterPostfix) and args.postfix_rule:
        output_formatter.rule = args.postfix_rule
    output = output_formatter.report(args.ip, asn, nets_for_as, args.skip_overlapping)

    if args.output_file:
        log.debug("Writing output to a file %s:" % args.output_file)
        with open(args.output_file, 'w') as output_file:
            output_file.write(output)
    else:
        log.debug("Printing the output:")
        print(output)


if __name__ == "__main__":
    main()
