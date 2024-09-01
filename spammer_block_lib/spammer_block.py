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

__author__ = 'Jari Turkia'
__email__ = 'jatu@hqcodeshop.fi'
__url__ = 'https://blog.hqcodeshop.fi/'
__git__ = 'https://github.com/HQJaTu/'
__version__ = '0.8'
__license__ = 'GPLv2'
__banner__ = 'cert_check_lib v{} ({})'.format(__version__, __git__)

from typing import Tuple, Union, List
from ipwhois import (
    IPWhois,
    Net as IPWhoisNet,
    exceptions as IPWhoisExceptions
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ipaddress import IPv4Address, IPv6Address, AddressValueError, IPv4Network, IPv6Network
from netaddr import IPNetwork, IPRange, IPAddress, iprange_to_cidrs, spanning_cidr
import logging
import os
import json
import html

from .datasources.datasource_base import DatasourceBase

log = logging.getLogger(__name__)


class SpammerBlock:
    DYNAMIC_AS_NUMBER_REPLACEMENT = '{ASN}'

    def __init__(self, datasource: DatasourceBase):
        self._datasource = datasource

    def whois_query(self, ip, asn: str = None,
                    asn_json_result_file: str = None,
                    allow_non_exact_merge: bool = False) -> Tuple[int, Union[None, dict]]:
        """
        Query networks contained in an AS-number.
        During post-processing make the networks as big as possible without overlap.
        :param ip: (optional, not needed if ASN given) IP-address to query for (IPv4 only? is IPv6 allowed?)
        :param asn: (optional, not needed if ASN given) AS-number to query for
        :param asn_json_result_file: If file exists, short-circuit and read previous query result from this file.
                                     If file not exist, query and write result to this file as JSON for next use.
        :param allow_non_exact_merge: don't require exact match on merge, resulting merged network will be inaccurate
        :return: tuple: int AS-number, dict of networks, key =
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
        net_data_out = self._post_process_asn_result(nets_data, allow_non_exact_merge)

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
        :return:
        """

        if asn_json_result_file and self.DYNAMIC_AS_NUMBER_REPLACEMENT in asn_json_result_file:
            asn_json_result_file_to_use = asn_json_result_file.format(ASN=asn)
        else:
            asn_json_result_file_to_use = asn_json_result_file
        # Query: Get list of all IP-ranges for given AS-number
        if asn_json_result_file:
            # From cache?
            if not os.path.exists(asn_json_result_file_to_use):
                log.warning("ASN JSON result file {} doesn't exist! Ignoring as input."
                            .format(asn_json_result_file_to_use))
            else:
                log.info("Using existing result file {}".format(asn_json_result_file_to_use))
                with open(asn_json_result_file_to_use) as json_file:
                    asn_data = json.load(json_file)

                # Sanity
                if 'asn' in asn_data:
                    # We have ipwhois.asn.IPASN result set
                    cached_asn = asn_data['asn']
                else:
                    if 'query' in asn_data:
                        # We have ipwhois.asn.ASNOrigin result set
                        cached_asn = asn_data['query']
                    else:
                        raise Exception("Invalid JSON-data read. Not valid ASN information!")
                if cached_asn != 'AS{}'.format(asn):
                    raise Exception(
                        "Invalid JSON-data read. This is for {}, expected AS{}!".format(cached_asn, asn))
                if 'nets' not in asn_data:
                    raise Exception("Invalid JSON-data read. Not valid Spammer-block cached ASN information!")
                asn_result = {
                    'nets': asn_data['nets']
                }

                return asn_result

        # Cache miss.
        # Go query.
        asn_result = self._datasource.lookup(asn)

        # Save if saving was requested and there is data to save.
        if asn_result and asn_json_result_file_to_use:
            log.info("Writing ASN JSON result file {}.".format(asn_json_result_file_to_use))
            with open(asn_json_result_file_to_use, "w") as asn_result_file:
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
                    log.debug("_process_asn_list() Net {} is IPv4".format(net))
                except AddressValueError:
                    try:
                        IPv6Network(net)
                        address_family = 6
                        log.debug("_process_asn_list() Net {} is IPv6".format(net))
                    except AddressValueError:
                        log.error("_process_asn_list() Net {} is neither IPv4 nor IPv6".format(net))
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
    def _post_process_asn_result(nets_data: dict, allow_non_exact_merge: bool) -> dict:
        log.debug("_post_process_asn_result(): Begin")

        # 1) Keep the list of CIDRs in a sorted list.
        #    Sorted networkwise, not alphabetically.
        sorted_nets = sorted(nets_data.keys(), key=SpammerBlock._ip_sort_helper)

        # 2) See if it is possible to combine results into fewer resulting nets
        ipv4_nets_set = set()
        ipv4_nets_to_merge = []
        ipv6_nets_set = set()
        ipv6_nets_to_merge = []
        for net_to_check, net_to_check_data in nets_data.items():
            if net_to_check_data['family'] == 4:
                ipv4_nets_set.add(IPv4Network(net_to_check))
                ipv4_nets_to_merge.append(IPNetwork(net_to_check))
            elif net_to_check_data['family'] == 6:
                ipv6_nets_set.add(IPv6Network(net_to_check))
                ipv6_nets_to_merge.append(IPNetwork(net_to_check))
            else:
                continue

        # Merge
        # Will result list of IPNetwork
        ipv4_nets_merged = SpammerBlock.netaddr_cidr_merge([(net, True) for net in ipv4_nets_to_merge], allow_non_exact_merge)
        ipv6_nets_merged = SpammerBlock.netaddr_cidr_merge([(net, True) for net in ipv6_nets_to_merge], allow_non_exact_merge)
        del ipv4_nets_to_merge  # IPNetwork-objects are not needed after this
        del ipv6_nets_to_merge

        sorted_nets_set = set(sorted_nets)
        ipv4_new_nets = [str(net[0].cidr) for net in ipv4_nets_merged if str(net[0].cidr) not in sorted_nets_set]
        ipv6_new_nets = [str(net[0].cidr) for net in ipv6_nets_merged if str(net[0].cidr) not in sorted_nets_set]

        net_data_out = {}

        log.debug("_post_process_asn_result(): Prep done")

        # Prepare the output data
        # 3.1) IPv4 networks
        for net_data in ipv4_nets_merged:
            net_to_check = net_data[0]
            net_is_exact = net_data[1]
            net_to_check_str = str(net_to_check.cidr)
            # Don't do those merged networks we've already done
            if net_to_check_str in net_data_out:
                continue

            net_to_check_obj = IPv4Network(net_to_check)
            if net_to_check_str not in ipv4_new_nets:
                # Not a new net, not a merged net
                net_data_out[net_to_check_str] = nets_data[net_to_check_str]
                net_data_out[net_to_check_str]['exact'] = True
                ipv4_nets_set.remove(net_to_check_obj)
                continue

            # This is a "new" network formed by merging existing results.
            net_data_out[net_to_check_str] = {
                'desc': '',
                'overlap': False,
                'exact': net_is_exact,
                'family': 4
            }

            # Add the "old" networks the newly merged network shadows.
            overlapping_nets = []
            overlapping_descs = []
            for other_net_to_check in ipv4_nets_set:
                if net_to_check_obj.overlaps(other_net_to_check):
                    overlapping_nets.append(other_net_to_check)
                    net = other_net_to_check.with_prefixlen
                    net_data_out[net] = nets_data[net]
                    net_data_out[net]['overlap'] = net_to_check_str
                    if nets_data[net]['desc']:
                        overlapping_descs.append(nets_data[net]['desc'])

            if overlapping_descs:
                # Add only unique descriptions
                net_data_out[net_to_check_str]['desc'] = ', '.join(list(set(overlapping_descs)))
            for net_to_remove in overlapping_nets:
                ipv4_nets_set.remove(net_to_remove)

            # New network done, go for next one

        log.debug("_post_process_asn_result(): IPv4 networks done")

        # 3.2) IPv6 networks
        for net_data in ipv6_nets_merged:
            net_to_check = net_data[0]
            net_is_exact = net_data[1]
            net_to_check_str = str(net_to_check.cidr)
            # Don't do those merged networks we've already done
            if net_to_check_str in net_data_out:
                continue

            net_to_check_obj = IPv6Network(net_to_check)
            if net_to_check_str not in ipv4_new_nets:
                # Not a new net, not a merged net
                net_data_out[net_to_check_str] = nets_data[net_to_check_str]
                net_data_out[net_to_check_str]['exact'] = True
                ipv6_nets_set.remove(net_to_check_obj)
                continue

            # This is a "new" network formed by merging existing results.
            net_data_out[net_to_check] = {
                'desc': '',
                'overlap': False,
                'exact': net_is_exact,
                'family': 6
            }

            # Add the "old" networks the newly merged network shadows.
            overlapping_nets = []
            overlapping_descs = []
            for other_net_to_check in ipv6_nets_set:
                if net_to_check_obj.overlaps(other_net_to_check):
                    overlapping_nets.append(other_net_to_check)
                    net = other_net_to_check.with_prefixlen
                    if net not in nets_data:
                        # Note: IPv4 data seems to be accurate, IPv6 not
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
                    net_data_out[net]['overlap'] = net_to_check_str
                    if nets_data[net]['desc']:
                        overlapping_descs.append(nets_data[net]['desc'])

            if overlapping_descs:
                # Add only unique descriptions
                net_data_out[net_to_check_str]['desc'] = ', '.join(list(set(overlapping_descs)))
            for net_to_remove in overlapping_nets:
                ipv6_nets_set.remove(net_to_remove)

            # New network done, go for next one

        log.debug("_post_process_asn_result() IPv6 networks done")
        log.debug("_post_process_asn_result(): Ready")

        return net_data_out

    @staticmethod
    def netaddr_cidr_merge(ip_addrs: List[Tuple[IPNetwork, bool]],
                           allow_non_exact_merge: bool) -> List[Tuple[IPNetwork, bool]]:
        """
        A function that accepts an iterable sequence of IP addresses and subnets
        merging them into the smallest possible list of CIDRs. It merges adjacent
        subnets where possible, those contained within others and also removes
        any duplicates.

        :param ip_addrs: an iterable sequence of IP addresses, subnets or ranges.
        :param allow_non_exact_merge: don't require exact match on merge, resulting merged network will be inaccurate
        :return: a summarized list of `IPNetwork` objects.
        """
        # The algorithm is quite simple: For each CIDR we create an IP range.
        # Sort them and merge when possible.  Afterwars split them again
        # optimally.

        ranges = []

        for ip_data in ip_addrs:
            net = ip_data[0]
            exactness = ip_data[1]
            if not isinstance(net, IPNetwork):
                raise ValueError("Expected IPNetwork-object as argument! Got {}".format(net.__class__))
            # Since non-overlapping ranges are the common case, remember the original
            ranges.append((
                net.version,
                net.last,
                net.first,
                exactness,
                net
            ))

        ranges.sort()
        i = len(ranges) - 1
        while i > 0:
            if ranges[i][0] == ranges[i - 1][0] and ranges[i][2] - 1 <= ranges[i - 1][1]:
                ranges[i - 1] = (
                    ranges[i][0],  # IP-version 4/6
                    ranges[i][1],  # last address
                    min(ranges[i - 1][2], ranges[i][2]),  # merged first address
                    ranges[i - 1][3] and ranges[i][3]  # exactness of resulting merged network
                    # original net object dropped
                )
                del ranges[i]
            i -= 1
        ranges_cnt = len(ranges)
        merged = []
        for range_tuple in ranges:
            # If this range wasn't merged we can simply use the old cidr.
            if len(range_tuple) == 5:
                exactness = range_tuple[3]
                original = range_tuple[4]
                if isinstance(original, IPRange):
                    merged.extend([(net, exactness) for net in original.cidrs()])
                else:
                    merged.append((original, exactness))
            else:
                version = range_tuple[0]
                exactness = range_tuple[3]
                range_start = IPAddress(range_tuple[2], version=version)
                range_stop = IPAddress(range_tuple[1], version=version)
                merged_nets = iprange_to_cidrs(range_start, range_stop)
                if not allow_non_exact_merge or len(merged_nets) == 1:
                    merged.extend([(net, exactness) for net in merged_nets])
                    continue

                # Approximations are allowed and needed. Rough results will be delivered.
                # log.warning("Inefficient merge: {}/{}".format(len(merged) + 1, ranges_cnt))
                merged_nets = spanning_cidr(merged_nets)
                merged.append((merged_nets, False))

        if not allow_non_exact_merge:
            return merged

        return SpammerBlock.netaddr_cidr_merge(merged, allow_non_exact_merge=False)

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
