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


import sys
import configargparse
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
    parser = configargparse.ArgumentParser(description='Block IP-ranges of a spammer',
                                     formatter_class=configargparse.RawTextHelpFormatter,
                                     default_config_files=['/etc/spammer-block/blocker.conf', '~/.spammer-blocker'])
    parser.add_argument('ip', metavar="IP",
                        help='IPv4 address to query for')
    parser.add_argument('--asn', '-a',
                        help='Skip querying for ASN')
    parser.add_argument('--skip-overlapping', '--merge-overlapping', action="store_true",
                        default=True,
                        help="Don't display any overlapping subnets. Larger network will be merged "
                             "to hide smaller ones. Default: yes")
    parser.add_argument('--allow-non-exact-overlapping', action="store_true",
                        default=False,
                        help="When merging overlapping, reduce number of networks by allowing non-exact merge. "
                             "Default: no")
    parser.add_argument('--output-format', '-o', default='postfix',
                        help='Output format. Choices: ' +
                             ', '.join(NET_LIST_OUTPUT_OPTIONS) + "\n" +
                             'Default: "postfix" will produce Postfix CIDR-table')
    parser.add_argument('--output-file',
                        help='Output to a file.')
    parser.add_argument('--postfix-rule', default=NetworkOutputPostfix.DEFAULT_POSTFIX_RULE,
                        help='CIDR-table rule to apply for a net.\n'
                             'Dynamic AS-number assignment with "{}".\n'
                             'Default: "{}"\n'
                             'Example: "PREPEND X-Spam-ASN: AS{{ASN}}"'.format(
                            NetworkOutputPostfix.DYNAMIC_AS_NUMBER_REPLACEMENT,
                            NetworkOutputPostfix.DEFAULT_POSTFIX_RULE
                        ))
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level (CRITICAL, FATAL, ERROR, WARNING, INFO, DEBUG). '
                             'Python default is: WARNING')
    parser.add_argument('--ipinfo-token',
                        help='ipinfo.io API access token for using paid ASN query service')
    parser.add_argument('--ipinfo-db-file',
                        help='ipinfo.io ASN DB file')
    parser.add_argument('--asn-result-json-file',
                        help='To conserve ASN-queries, save query result\n'
                             'or use existing result from a previous query.\n'
                             'Dynamic AS-number assignment with "{}".'.format(
                            SpammerBlock.DYNAMIC_AS_NUMBER_REPLACEMENT
                        ))
    parser.add_argument("-c", "--config-file",
                        is_config_file=True,
                        help="Specify config file", metavar="FILE")
    args = parser.parse_args()

    _setup_logger(args.log_level)

    # Select datasource
    #ds = datasources.RADb(args.ip)
    ds = datasources.IPInfoIO(args.ip, token=args.ipinfo_token, db_file=args.ipinfo_db_file)

    # Go process
    spammer_blocker = SpammerBlock(ds)
    asn, nets_for_as = spammer_blocker.whois_query(args.ip,
                                                   asn=args.asn,
                                                   asn_json_result_file=args.asn_result_json_file,
                                                   allow_non_exact_merge=args.allow_non_exact_overlapping)

    # Go output
    output_formatter_class = NET_LIST_OUTPUT_OPTIONS.get(args.output_format, NetworkOutputNone)
    output_formatter = output_formatter_class()
    if isinstance(output_formatter, NetworkOutputPostfix) and args.postfix_rule:
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
