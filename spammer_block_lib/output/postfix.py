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

from .abstract import NetworkOutputAbstract


class NetworkOutputPostfix(NetworkOutputAbstract):
    DEFAULT_POSTFIX_RULE = "554 Go away spammer!"
    DYNAMIC_AS_NUMBER_REPLACEMENT = '{ASN}'

    def __init__(self, rule: str = DEFAULT_POSTFIX_RULE):
        self.rule = rule

    def _do_report(self, ip: str, asn: int, nets: dict, skip_overlap: bool):
        """
        Produce CIDR-table
        Docs: https://www.postfix.org/cidr_table.5.html
        :param ip: IP-address where spam originated
        :param asn: AS-number to stamp into report
        :param nets: List of networks belonging to AS-number
        :param skip_overlap: Create shorter list and skip any overlapping networks
        :return:
        """
        report = "# Confirmed spam from IP: {}\n".format(ip)
        report += "# AS{} has following nets:\n".format(asn)

        rule = self.rule
        if self.DYNAMIC_AS_NUMBER_REPLACEMENT in self.rule:
            rule = self.rule.format(ASN=asn)
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
                desc = "\t# {}".format(net_data['desc'])
            if net_data['overlap']:
                line_in_comment = '#'
                if not desc:
                    desc = "\t# {}".format(net_data['overlap'])
                else:
                    desc = "\t# (overlap: {}) {}".format(net_data['overlap'], net_data['desc'])
            report += "{0:s}{1:s}\t{2:s}{3:s}{4:s}\n".format(
                line_in_comment, net, '\t' * tabs,
                rule, desc
            )

        return report
