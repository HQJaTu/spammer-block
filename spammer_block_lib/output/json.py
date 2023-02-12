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


class NetworkOutputJson(NetworkOutputAbstract):

    def _do_report(self, ip: str, asn: int, nets: dict, skip_overlap: bool) -> str:
        """
        Raw output of network data
        :param ip: IP-address where spam originated
        :param asn: AS-number to stamp into report
        :param nets: List of networks belonging to AS-number
        :param skip_overlap: Create shorter list and skip any overlapping networks
        :return:
        """
        import json

        if skip_overlap:
            nets_in = nets
        else:
            nets_in = {net for net, net_data in nets.items() if not net_data['overlap']}

        nets_out = {'confirmed_ip': ip, 'asn': asn, 'nets': nets_in}
        json = json.dumps(nets_out, indent=4)

        return json
