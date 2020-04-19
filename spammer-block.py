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


def output_postfix(ip, asn, nets, skip_overlap):
    if not nets:
        sys.stderr.write("No nets found for IPv4 %s, ASN %s! Cannot continue." % (ip, asn))
        exit(1)

    print("# Confirmed spam from IP: %s" % ip)
    print("# AS%d has following nets:" % asn)

    format_max_net_len = 0
    for net, net_data in nets.items():
        length = len(net)
        if net_data['overlap']:
            length += 1
        if length > format_max_net_len:
            format_max_net_len = length
    format_max_tabs = int(format_max_net_len / 8)
    for net, net_data in nets.items():
        length = len(net)
        if net_data['overlap']:
            if skip_overlap:
                continue
            length += 1
        tabs = format_max_tabs - int(length / 8)
        line_in_comment = ''
        desc = ''
        if net_data['desc']:
            desc = "\t# %s" % net_data['desc']
        if net_data['overlap']:
            line_in_comment = '#'
            if not desc:
                desc = "\t# %s" % net_data['overlap']
            else:
                desc = "\t# (overlap: %s) %s" % (net_data['overlap'], net_data['desc'])
        print("%s%s\t%s554 Go away spammer!%s" % (line_in_comment, net, '\t' * tabs, desc))


def output_json(ip, asn, nets, skip_overlap):
    import json

    nets_out = {'confirmed_ip': ip, 'asn': asn, 'nets': nets}
    print(json.dumps(nets_out, indent=4))


def output_none(ip, asn, nets, skip_overlap):
    pass


def main():
    parser = argparse.ArgumentParser(description='Block IP-ranges of a spammer')
    parser.add_argument('--ip', '-i', required=True,
                        help='IPv4 address to query for')
    parser.add_argument('--skip-overlapping', action="store_true",
                        default=False,
                        help="Don't display any overlapping subnets")
    parser.add_argument('--output', '-o', default='postfix',
                        help='Output format. Default "postfix"')
    parser.add_argument('--log',
                        help='Set logging level. Python default is: WARNING')
    parser.add_argument('--ipinfo-token', default=None,
                        help='ipinfo.io API access token if using paid ASN query service')
    parser.add_argument('--debug-asn-result-file', default=None,
                        help='Debugging: To conserve ASN-queries, use existing result from a cache file.')

    args = parser.parse_args()
    output_choices = {'postfix': output_postfix, 'json': output_json}

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
    spammer_blocker = SpammerBlock(token=args.ipinfo_token)
    asn, nets_for_as = spammer_blocker.whois_query(args.ip, asn_cache_file=args.debug_asn_result_file)
    output_formatter = output_choices.get(args.output, output_none)
    output_formatter(args.ip, asn, nets_for_as, args.skip_overlapping)


if __name__ == "__main__":
    main()
