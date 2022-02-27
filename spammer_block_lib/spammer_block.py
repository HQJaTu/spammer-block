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
__version__ = '0.5'
__license__ = 'GPLv2'
__banner__ = 'cert_check_lib v{} ({})'.format(__version__, __git__)

from typing import Tuple, Union
from ipwhois import (
    IPWhois,
    Net as IPWhoisNet,
    exceptions as IPWhoisExceptions
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network
from netaddr import cidr_merge as netaddr_cidr_merge, IPNetwork
import logging
import os
import json
import html

from .datasources.datasource_base import DatasourceBase

log = logging.getLogger(__name__)


class SpammerBlock:
    ipinfo_token = None

    def __init__(self, datasource: DatasourceBase):
        self._datasource = datasource

    def whois_query(self, ip, asn: str = None,
                    asn_json_result_file: str = None) -> Tuple[int, Union[None, dict]]:
        """
        Query networks contained in an AS-number.
        During post-processing make the networks as big as possible without overlap.
        :param ip: (optional, not needed if ASN given) IP-address to query for (IPv4 only? is IPv6 allowed?)
        :param asn: (optional, not needed if ASN given) AS-number to query for
        :param asn_json_result_file: If file exists, short-circuit and read previous query result from this file.
                                     If file not exist, query and write result to this file as JSON for next use.
        :return: dict of networks
        """
        if not asn:
            # Convert input IP into AS-number
            asn, ip_result = self._asn_query(ip)
        else:
            ip_result = None
            if asn[:2] == "AS":
                asn = int(asn[2:])
            else:
                asn = int(asn)
            if not asn:
                raise ValueError("Need valid ASN!")

        asn_result = self._ranges_for_asn(asn, asn_json_result_file)
        if not asn_result:
            return asn, None

        nets_data = self._process_asn_list(asn, asn_result, ip_result)
        net_data_out = self._post_process_asn_result(nets_data)

        return asn, net_data_out

    @staticmethod
    def _asn_query(ip) -> Tuple[int, dict]:
        # Query 1:
        # Get AS-number for given IP
        # ip_whois_query = IPWhois(ip, allow_permutations=False)
        ip_whois_query = IPWhois(ip)
        ip_result = ip_whois_query.lookup_rdap(asn_methods=["whois"], get_asn_description=False)

        asn = int(ip_result['asn'])
        log.debug("Got AS{} for CIDR {}".format(asn, ip_result['asn_cidr']))

        return asn, ip_result

    def _ranges_for_asn(self, asn: int, asn_json_result_file: str) -> dict:
        """

        :param ip:
        :param asn: AS-number to query
        :param asn_json_result_file: If exists, don't query, use previously saved cache data
        :param short_circuit_asn_result: Don't query, use this JSON data from external source
        :return:
        """

        # Query 2:
        # Get list of all IP-ranges for given AS-number

        if asn_json_result_file:
            # From cache?
            if not os.path.exists(asn_json_result_file):
                log.warning("ASN JSON result file {} doesn't exist! Ignoring.".format(asn_json_result_file))
            else:
                log.info("Using existing result file {}".format(asn_json_result_file))
                with open(asn_json_result_file) as json_file:
                    asn_data = json.load(json_file)

                # Sanity
                if 'asn' not in asn_data:
                    raise Exception("Invalid JSON-data read. Not valid ASN information!")
                if asn_data['asn'] != 'AS{}'.format(asn):
                    raise Exception(
                        "Invalid JSON-data read. This is for {}, expected AS{}!".format(asn_data['asn'], asn))
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

                return asn_result

        # Note: IP-address really isn't a factor here, but IPWhoisASNOrigin class requires a net.
        #       Any net will do for ASN-queries.
        # net = IPWhoisNet(ip, allow_permutations=False)
        asn_result = self._datasource.lookup(asn)

        if asn_result and asn_json_result_file:
            # Don't save nothingness.
            with open(asn_json_result_file, "w") as asn_result_file:
                asn_result_file.write(json.dumps(asn_result))

        return asn_result

    @staticmethod
    def _process_asn_list(asn: int, asn_result: dict, ip_result_fallback: dict) -> dict:
        # Query 3:
        # Just harvest the CIDR-numbers from previous listing.
        nets_data = {}
        if asn_result['nets']:
            # Plan A:
            # Have network list in the result
            log.debug("Got nets for AS{0:d}".format(asn))
            for net_info in asn_result['nets']:
                net = net_info['cidr']

                address_family = None
                try:
                    IPv4Network(net)
                    address_family = 4
                    log.debug("Net {} is IPv4".format(net))
                except AddressValueError:
                    try:
                        IPv6Network(net)
                        address_family = 6
                        log.debug("Net {} is IPv6".format(net))
                    except AddressValueError:
                        log.error("Net {} is neither IPv4 nor IPv6".format(net))
                        raise

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
        elif ip_result_fallback and 'asn_cidr' in ip_result_fallback and ip_result_fallback['asn_cidr']:
            # Plan B:
            # Sometimes querying by AS-number doesn't yield any results.
            # Also, sometimes the IP-result has the nets in it.
            log.debug("No nets for AS{}".format(asn))
            net = ip_result_fallback['asn_cidr']
            nets_data[net] = {
                'desc': 'AS{}-query-failed-info-from-whois: {}-'.format(asn, ip_result_fallback['asn_description']),
                'overlap': False,
                'family': None
            }

        return nets_data

    @staticmethod
    def _post_process_asn_result(nets_data) -> dict:

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
                        if net not in nets_data:
                            log.warning("Internal: When checking merged net {}, "
                                        "matching it with {} not found!".format(net_to_check, net)
                                        )
                            # import pprint
                            # pp = pprint.PrettyPrinter(indent=4)
                            # pp.pprint(net)
                            # pp.pprint(other_net_to_check)
                            # pp.pprint(nets_data)
                            # raise Exception("Internal: %s not found!" % net)
                            continue
                        net_data_out[net] = nets_data[net]
                        net_data_out[net]['overlap'] = net_to_check

                # New network done, go for next one
                continue

            # Not a new net, not a merged net
            net_data_out[net_to_check] = nets_data[net_to_check]

        return net_data_out

    @staticmethod
    def _ip_sort_helper(item) -> int:
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

        raise ValueError("Cannot detect '{}' as IPv4 nor IPv6 address".format(item))
