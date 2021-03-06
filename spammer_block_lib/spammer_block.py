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
__version__ = '0.4.3'
__license__ = 'GPLv2'
__banner__ = 'cert_check_lib v%s (%s)' % (__version__, __git__)

from ipwhois import (
    IPWhois,
    Net as IPWhoisNet,
    exceptions as IPWhoisExceptions
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network
from netaddr import cidr_merge as netaddr_cidr_merge, IPNetwork
import logging
import pickle
import os
import json
import html

log = logging.getLogger(__name__)


class SpammerBlock:
    ipinfo_token = None

    def __init__(self, token=None):
        self.ipinfo_token = token

    def whois_query(self, ip, asn_cache_file=None, asn_json_result_file=None):
        # Query 1:
        # Get AS-number for given IP
        #ip_whois_query = IPWhois(ip, allow_permutations=False)
        ip_whois_query = IPWhois(ip)
        ip_result = ip_whois_query.lookup_rdap(asn_methods=["whois"], get_asn_description=False)

        asn = int(ip_result['asn'])
        log.debug("Got AS%d for CIDR %s" % (asn, ip_result['asn_cidr']))

        # Query 2:
        # Get list of all IP-ranges for given AS-number
        # Note: IP-address really isn't a factor here, but IPWhoisASNOrigin class requires a net.
        #       Any net will do for ASN-queries.
        #net = IPWhoisNet(ip, allow_permutations=False)
        net = IPWhoisNet(ip)
        if hasattr(IPWhoisASNOrigin, 'ASN_SOURCE_HTTP_IPINFO'):
            log.debug("Query HTTP from IPinfo.io")
            if not self.ipinfo_token:
                log.error("Attempt to use ipinfo.io API without token")
            # JaTu: https://github.com/HQJaTu/ipwhois/tree/ipinfo.io
            asn_query = IPWhoisASNOrigin(net, token=self.ipinfo_token)
            # methods = [IPWhoisASNOrigin.ASN_SOURCE_WHOIS, IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
            methods = [IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
            can_fallback_radb = True
        else:
            log.debug("Query HTTP from RADb")
            if self.ipinfo_token:
                log.warning("Using RADb for ASN-query. Ignoring ipinfo.io API token.")
            # Original: https://github.com/secynic/ipwhois
            asn_query = IPWhoisASNOrigin(net)
            methods = ['http']
            can_fallback_radb = False

        if asn_cache_file:
            if not os.path.exists(asn_cache_file):
                log.warning("ASN cache file %s doesn't exist! Ignoring." % asn_cache_file)
            else:
                log.debug("Using cached file")
        if asn_json_result_file:
            if not os.path.exists(asn_json_result_file):
                log.warning("ASN JSON result file %s doesn't exist! Ignoring." % asn_json_result_file)
            else:
                log.debug("Using existing result file")
        if asn_cache_file and os.path.exists(asn_cache_file):
            with open(asn_cache_file, "rb") as asn_result_file:
                asn_result = pickle.load(asn_result_file)
        elif asn_json_result_file and os.path.exists(asn_json_result_file):
            with open(asn_json_result_file) as json_file:
                asn_data = json.load(json_file)

            # Sanity
            if 'asn' not in asn_data:
                raise Exception("Invalid JSON-data read. Not valid ASN information!")
            if asn_data['asn'] != 'AS%d' % asn:
                raise Exception("Invalid JSON-data read. This is for %s, expected AS%d!" % (asn_data['asn'], asn))
            if 'prefixes' not in asn_data:
                raise Exception("Invalid JSON-data read. Not valid ASN information!")
            asn_result = {
                'nets': []
            }
            for net_info in asn_data['prefixes']:
                prefix = net_info["netblock"]
                net_name = net_info["name"]
                net_info_out = {
                    'cidr': prefix,
                    'description': net_name
                }
                asn_result['nets'].append(net_info_out)
        else:
            try:
                asn_result = asn_query.lookup(asn='AS%d' % asn, asn_methods=methods)
            except IPWhoisExceptions.ASNOriginLookupError as e:
                if not can_fallback_radb:
                    raise e
                asn_query = IPWhoisASNOrigin(net)
                methods = ['http']
                asn_result = asn_query.lookup(asn='AS%d' % asn, asn_methods=methods)
            if asn_cache_file:
                with open(asn_cache_file, "wb") as asn_result_file:
                    pickle.dump(asn_result, asn_result_file)

        # Query 3:
        # Just harvest the CIDR-numbers from previous listing.
        nets_data = {}
        if asn_result['nets']:
            log.debug("Got nets for AS%d" % asn)
            for net_info in asn_result['nets']:
                net = net_info['cidr']

                address_family = None
                try:
                    IPv4Network(net)
                    address_family = 4
                    log.debug("Net %s is IPv4" % net)
                except AddressValueError:
                    try:
                        IPv6Network(net)
                        address_family = 6
                        log.debug("Net %s is IPv6" % net)
                    except AddressValueError:
                        log.debug("Net %s is neither IPv4 nor IPv6" % net)

                if net_info['description'] and True:
                    # All methods will use HTML
                    # If a description exist, make sure HTML-entities are unescaped.
                    desc = html.unescape(net_info['description'])
                else:
                    desc = net_info['description']

                nets_data[net] = {
                    'desc': desc,
                    'overlap': False,
                    'family': address_family
                }
        elif ip_result['asn_cidr']:
            # Sometimes querying by AS-number doesn't yield any results.
            log.debug("No nets for AS%d" % asn)
            net = ip_result['asn_cidr']
            nets_data[net] = {
                'desc': '-ASN-query-failed-info-from-whois: %s-' % ip_result['asn_description'],
                'overlap': False,
                'family': None
            }

        # Post-process

        # 1) Keep the list of CIDRs in a sorted list.
        #    Sorted networkwise, not alphabetically.
        sorted_nets = sorted(nets_data.keys(), key=SpammerBlock._ip_sort_helper)

        # 2) See if it is possible to combine results into fewer resulting nets
        ipv4_nets = []
        ipv6_nets = []
        for net_to_check, net_to_check_data in nets_data.items():
            if net_to_check_data['family'] == 4:
                ipv4_nets.append(IPNetwork(net_to_check))
            elif net_to_check_data['family'] == 6:
                ipv6_nets.append(IPNetwork(net_to_check))
            else:
                continue

        ipv4_nets_merged = netaddr_cidr_merge(ipv4_nets)
        ipv6_nets_merged = netaddr_cidr_merge(ipv6_nets)

        ipv4_nets_merged = [str(net.cidr) for net in ipv4_nets_merged]
        ipv6_nets_merged = [str(net.cidr) for net in ipv6_nets_merged]

        ipv4_new_nets = [net for net in ipv4_nets_merged if net not in set(sorted_nets)]
        ipv6_new_nets = [net for net in ipv6_nets_merged if net not in set(sorted_nets)]

        net_data_out = {}

        # Prepare the output data
        # 3.1) IPv4 networks
        for net_to_check in ipv4_nets_merged:
            # Don't do those merged networks we've already done
            if net_to_check in net_data_out:
                continue

            net_to_check_obj = IPv4Network(net_to_check)
            if net_to_check in ipv4_new_nets:
                # This is a "new" network formed by merging existing results.
                net_data_out[net_to_check] = {
                    'desc': '',
                    'overlap': False,
                    'family': 4
                }

                # Add the "old" networks the newly merged network shadows.
                for other_net_to_check in ipv4_nets:
                    net = str(other_net_to_check.cidr)
                    other_net_to_check_obj = IPv4Network(net)
                    if net_to_check_obj.overlaps(other_net_to_check_obj):
                        net_data_out[net] = nets_data[net]
                        net_data_out[net]['overlap'] = net_to_check

                # New network done, go for next one
                continue

            # Not a new net, not a merged net
            net_data_out[net_to_check] = nets_data[net_to_check]

        # 3.2) IPv6 networks
        for net_to_check in ipv6_nets_merged:
            # Don't do those merged networks we've already done
            if net_to_check in net_data_out:
                continue

            net_to_check_obj = IPv6Network(net_to_check)
            if net_to_check in ipv6_new_nets:
                # This is a "new" network formed by merging existing results.
                net_data_out[net_to_check] = {
                    'desc': '',
                    'overlap': False,
                    'family': 6
                }

                # Add the "old" networks the newly merged network shadows.
                for other_net_to_check in ipv6_nets:
                    net = str(other_net_to_check.cidr)
                    if net == net_to_check:
                        # No sense of matching same nets
                        continue
                    other_net_to_check_obj = IPv6Network(net)
                    if net_to_check_obj.overlaps(other_net_to_check_obj):
                        if not net in nets_data:
                            log.warning("Internal: When checking merged net %s, matching it with %s not found!" % (net_to_check, net))
                            #import pprint
                            #pp = pprint.PrettyPrinter(indent=4)
                            #pp.pprint(net)
                            #pp.pprint(other_net_to_check)
                            #pp.pprint(nets_data)
                            #raise Exception("Internal: %s not found!" % net)
                            continue
                        net_data_out[net] = nets_data[net]
                        net_data_out[net]['overlap'] = net_to_check

                # New network done, go for next one
                continue

            # Not a new net, not a merged net
            net_data_out[net_to_check] = nets_data[net_to_check]

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
