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
from ipwhois import (
    IPWhois,
    Net as IPWhoisNet
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network
from collections import OrderedDict
from netaddr import cidr_merge as netaddr_cidr_merge, IPNetwork
import warnings


def _ip_sort_helper(item):
    """
    See: https://stackoverflow.com/questions/48981416/find-ipv4-and-ignore-ipv6-ip-addresses-with-python
    See: https://stackoverflow.com/questions/6545023/how-to-sort-ip-addresses-stored-in-dictionary-in-python
    :param item:
    :return:
    """

    ip = item.split('/')[0]
    try:
        return int(IPv4Address(ip))
    except AddressValueError:
        pass

    try:
        return int(IPv6Address(ip))
    except AddressValueError:
        pass

    raise ValueError("Cannot detect '%s' as IPv4 nor IPv6 address" % item)


def whois_query(ip):
    # Pass 1:
    # Get AS-number for given IP
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        # Note: This is a noisy bugger for reasons nobody can comprehend.
        obj = IPWhois(ip, allow_permutations=False)
        ip_result = obj.lookup_rdap(asn_methods=["whois"], get_asn_description=False)

    asn = int(ip_result['asn'])
    # print("Got AS%d for CIDR %s" % (asn, ip_result['asn_cidr']))

    # Pass 2:
    # Get list of all IP-ranges for given AS-number
    # Note: IP-address really isn't a factor here, but IPWhoisASNOrigin class requires a net.
    #       Any net will do for ASN-queries.
    net = IPWhoisNet(ip, allow_permutations=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        obj = IPWhoisASNOrigin(net)
        # methods = ['http']
        # methods = [IPWhoisASNOrigin.ASN_SOURCE_WHOIS, IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
        methods = [IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
        # ASN enabled token required!
        # obj.ipinfo_token = 'a78d9125e599a0'

        asn_result = obj.lookup(asn='AS%d' % asn, asn_methods=methods)

    # Pass 3:
    # Just harvest the CIDR-numbers from previous listing and sort them by IP-address.
    # print(asn_result)
    nets_data = {}
    if asn_result['nets']:
        for net_info in asn_result['nets']:
            net = net_info['cidr']
            # print(net)
            # print(net_info['description'])
            nets_data[net] = net_info['description']
    elif ip_result['asn_cidr']:
        # Sometimes querying by AS-number doesn't yield any results.
        net = ip_result['asn_cidr']
        nets_data[net] = '-ASN-query-failed-info-from-whois: %s-' % ip_result['asn_description']

    # Check for overlap
    # 1) Create an ordered dict of all the networks received by AS-number.
    sorted_nets = sorted(nets_data.keys(), key=_ip_sort_helper)
    sorted_nets_data = OrderedDict(
        [(key, {'desc': nets_data[key], 'overlap': False, 'family': None}) for key in sorted_nets])
    # print(sorted_nets_data)

    # 2) Match the IP-address families from AS-result CIDRs
    for net_to_check in sorted_nets:
        try:
            IPv4Network(net_to_check)
            sorted_nets_data[net_to_check]['family'] = 4
            continue
        except AddressValueError:
            pass

        try:
            IPv6Network(net_to_check)
            sorted_nets_data[net_to_check]['family'] = 6
            continue
        except AddressValueError:
            pass

    # 3) See if there is any overlap between results
    #    Drop any small nets shadowed by bigger ones
    for net_to_check, net_to_check_data in sorted_nets_data.items():
        if net_to_check_data['family'] == 4:
            net_to_check_obj = IPv4Network(net_to_check)
        elif net_to_check_data['family'] == 6:
            net_to_check_obj = IPv6Network(net_to_check)
        else:
            continue

        for other_net_to_check, other_net_to_check_data in sorted_nets_data.items():
            # Don't bother checking myself
            if other_net_to_check == net_to_check:
                continue
            # Don't bother checking other address families
            if net_to_check_data['family'] != other_net_to_check_data['family']:
                continue

            if other_net_to_check_data['family'] == 4:
                other_net_to_check_obj = IPv4Network(other_net_to_check)
            elif other_net_to_check_data['family'] == 6:
                other_net_to_check_obj = IPv6Network(other_net_to_check)
            else:
                continue

            if net_to_check_obj.overlaps(other_net_to_check_obj):
                if net_to_check_obj.netmask < other_net_to_check_obj.netmask:
                    sorted_nets_data[other_net_to_check]['overlap'] = net_to_check
                else:
                    sorted_nets_data[net_to_check]['overlap'] = other_net_to_check

    # 4) See if it is possible to combine results into fewer resulting nets
    ipv4_nets = []
    ipv6_nets = []
    for net_to_check, net_to_check_data in sorted_nets_data.items():
        if net_to_check_data['family'] == 4:
            ipv4_nets.append(IPNetwork(net_to_check))
        elif net_to_check_data['family'] == 6:
            ipv6_nets.append(IPNetwork(net_to_check))
        else:
            continue

    ipv4_nets_merged = netaddr_cidr_merge(ipv4_nets)
    ipv6_nets_merged = netaddr_cidr_merge(ipv6_nets)
    net_data_out = OrderedDict()

    # 4.1) IPv4 networks
    for net in ipv4_nets_merged:
        net_to_check = str(net.cidr)
        net_to_check_obj = IPv4Network(net_to_check)
        desc = []

        for other_net_to_check, other_net_to_check_data in sorted_nets_data.items():
            # Don't bother checking myself
            if other_net_to_check == net_to_check:
                continue
            # Don't bother checking other address families
            if 4 != other_net_to_check_data['family']:
                continue
            other_net_to_check_obj = IPv4Network(other_net_to_check)

            if net_to_check_obj.overlaps(other_net_to_check_obj):
                desc.append(other_net_to_check_data['desc'])

        net_data_out[net_to_check] = {
            'desc': ', '.join(desc),
            'overlap': False,
            'family': None
        }

    # 4.2) IPv6 networks
    for net in ipv6_nets_merged:
        net_to_check = str(net.cidr)
        net_to_check_obj = IPv6Network(net_to_check)
        desc = []

        for other_net_to_check, other_net_to_check_data in sorted_nets_data.items():
            # Don't bother checking myself
            if other_net_to_check == net_to_check:
                continue
            # Don't bother checking other address families
            if 6 != other_net_to_check_data['family']:
                continue
            other_net_to_check_obj = IPv6Network(other_net_to_check)

            if net_to_check_obj.overlaps(other_net_to_check_obj):
                desc.append(other_net_to_check_data['desc'])

        net_data_out[net_to_check] = {
            'desc': ', '.join(desc),
            'overlap': False,
            'family': None
        }

    return asn, net_data_out


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

    args = parser.parse_args()
    output_choices = {'postfix': output_postfix, 'json': output_json}

    asn, nets_for_as = whois_query(args.ip)
    output_formatter = output_choices.get(args.output, output_none)
    output_formatter(args.ip, asn, nets_for_as, args.skip_overlapping)


if __name__ == "__main__":
    main()
