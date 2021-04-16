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
    parser = argparse.ArgumentParser(description='Block IP-ranges of a spammer')
    parser.add_argument('ip', metavar="IP",
                        help='IPv4 address to query for')
    parser.add_argument('--asn', '-a',
                        help='Skip querying for ASN')
    parser.add_argument('--skip-overlapping', action="store_true",
                        default=True,
                        help="Don't display any overlapping subnets. Default: yes")
    parser.add_argument('--output-format', '-o', default='postfix',
                        help='Output format. Default "postfix"')
    parser.add_argument('--output-file',
                        help='Output to a file.')
    parser.add_argument('--log',
                        help='Set logging level. Python default is: WARNING')
    parser.add_argument('--ipinfo-token', default=None,
                        help='ipinfo.io API access token if using paid ASN query service')
    #parser.add_argument('--debug-write-asn-result-to-file',
    #                    help='Debugging: To conserve ASN-queries, write result to a cache file.')
    parser.add_argument('--asn-result-cache-file',
                        help='Debugging: To conserve ASN-queries, use existing result from a Python cached file.')
    parser.add_argument('--short-circuit-asn-result-json-file',
                        help='Debugging: To conserve ASN-queries, use existing result from JSON file.')

    args = parser.parse_args()

    if args.log:
        log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(log_formatter)
        logging.getLogger().addHandler(console_handler)
        print("Set logging level into: %s" % args.log)
        asn_log = logging.getLogger('ipwhois.asn')
        spammer_log = logging.getLogger('spammer_block_lib.spammer_block')
        asn_log.setLevel(args.log)
        spammer_log.setLevel(args.log)
    else:
        asn_log = None

    # Go process
    spammer_blocker = SpammerBlock(token=args.ipinfo_token)
    asn, nets_for_as = spammer_blocker.whois_query(args.ip,
                                                   asn=args.asn,
                                                   asn_cache_file=args.asn_result_cache_file,
                                                   asn_json_result_file=args.short_circuit_asn_result_json_file)

    # Go output
    output_formatter_class = OUTPUT_OPTIONS.get(args.output_format, SpammerReporterNone)
    output_formatter = output_formatter_class()
    output = output_formatter.report(args.ip, asn, nets_for_as, args.skip_overlapping)

    if args.output_file:
        if asn_log:
            asn_log.debug("Writing output to a file %s:" % args.output_file)
        with open(args.output_file, 'w') as output_file:
            output_file.write(output)
    else:
        if asn_log:
            asn_log.debug("Printing the output:")
        print(output)


if __name__ == "__main__":
    main()
