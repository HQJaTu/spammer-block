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

__author__ = 'Jari Turkia'
__email__ = 'jatu@hqcodeshop.fi'
__url__ = 'https://blog.hqcodeshop.fi/'
__git__ = 'https://github.com/HQJaTu/'
__version__ = '0.3'
__license__ = 'GPLv2'
__banner__ = 'cert_check_lib v%s (%s)' % (__version__, __git__)

from ipwhois import (
    IPWhois,
    Net as IPWhoisNet
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network
from collections import OrderedDict
from netaddr import cidr_merge as netaddr_cidr_merge, IPNetwork
import logging
import pickle
import os

log = logging.getLogger(__name__)


class SpammerBlock:

    ipinfo_token = None

    def __init__(self, token=None):
        self.ipinfo_token = token

    def whois_query(self, ip, asn_cache_file=None):
        # Query 1:
        # Get AS-number for given IP
        ip_whois_query = IPWhois(ip, allow_permutations=False)
        ip_result = ip_whois_query.lookup_rdap(asn_methods=["whois"], get_asn_description=False)

        asn = int(ip_result['asn'])
        log.debug("Got AS%d for CIDR %s" % (asn, ip_result['asn_cidr']))

        # Query 2:
        # Get list of all IP-ranges for given AS-number
        # Note: IP-address really isn't a factor here, but IPWhoisASNOrigin class requires a net.
        #       Any net will do for ASN-queries.
        net = IPWhoisNet(ip, allow_permutations=False)
        asn_query = IPWhoisASNOrigin(net, token=self.ipinfo_token)
        # Original: https://github.com/secynic/ipwhois
        # methods = ['http']
        # JaTu: https://github.com/HQJaTu/ipwhois/tree/ipinfo.io
        # methods = [IPWhoisASNOrigin.ASN_SOURCE_WHOIS, IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
        methods = [IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]

        if asn_cache_file and os.path.exists(asn_cache_file):
            with open(asn_cache_file, "rb") as asn_result_file:
                asn_result = pickle.load(asn_result_file)
        else:
            asn_result = asn_query.lookup(asn='AS%d' % asn, asn_methods=methods)
            if asn_cache_file:
                with open(asn_cache_file, "wb") as asn_result_file:
                    pickle.dump(asn_result, asn_result_file)

        # Query 3:
        # Just harvest the CIDR-numbers from previous listing and sort them by IP-address.
        nets_data = {}
        if asn_result['nets']:
            for net_info in asn_result['nets']:
                net = net_info['cidr']
                nets_data[net] = net_info['description']
        elif ip_result['asn_cidr']:
            # Sometimes querying by AS-number doesn't yield any results.
            net = ip_result['asn_cidr']
            nets_data[net] = '-ASN-query-failed-info-from-whois: %s-' % ip_result['asn_description']

        # Post-process

        # Check for overlap
        # 1) Create an ordered dict of all the networks received by AS-number.
        sorted_nets = sorted(nets_data.keys(), key=SpammerBlock._ip_sort_helper)
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

    @staticmethod
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
