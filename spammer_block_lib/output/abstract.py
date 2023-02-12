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

from abc import ABC, abstractmethod


class NetworkOutputAbstract(ABC):

    def report(self, ip: str, asn: int, nets: dict, skip_overlap: bool) -> str:
        if not nets:
            raise ValueError("No nets found for IPv4 {}, AS{}! Cannot continue.".format(ip, asn))

        return self._do_report(ip, asn, nets, skip_overlap)

    @abstractmethod
    def _do_report(self, ip: str, asn: int, nets: dict, skip_overlap: bool) -> str:
        raise NotImplemented("This is an abstract class!")
