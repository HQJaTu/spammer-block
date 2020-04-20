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


class SpammerReporterAbstract:

    def report(self, ip, asn, nets, skip_overlap):
        if not nets:
            raise ValueError("No nets found for IPv4 %s, ASN %s! Cannot continue." % (ip, asn))

        return self._do_report(ip, asn, nets, skip_overlap)

    def _do_report(self, ip, asn, nets, skip_overlap):
        raise NotImplemented("This is an abstract class!")


class SpammerReporterNone(SpammerReporterAbstract):

    def _do_report(self, ip, asn, nets, skip_overlap):
        pass


class SpammerReporterJson(SpammerReporterAbstract):

    def _do_report(self, ip, asn, nets, skip_overlap):
        import json

        nets_out = {'confirmed_ip': ip, 'asn': asn, 'nets': nets}
        json = json.dumps(nets_out, indent=4)

        return json


class SpammerReporterPostfix(SpammerReporterAbstract):

    def _do_report(self, ip, asn, nets, skip_overlap):
        report = "# Confirmed spam from IP: %s\n" % ip
        report += "# AS%d has following nets:\n" % asn

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
            report += "%s%s\t%s554 Go away spammer!%s\n" % (line_in_comment, net, '\t' * tabs, desc)

        return report


OUTPUT_OPTIONS = {
    'none': SpammerReporterNone,
    'json': SpammerReporterJson,
    'postfix': SpammerReporterPostfix
}
