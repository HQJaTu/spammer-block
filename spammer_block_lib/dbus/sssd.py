# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

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

from typing import Generator, Tuple
from dbus import (Bus, SessionBus, SystemBus, Interface, proxies)
import logging

log = logging.getLogger(__name__)
SSSD_INFOPIPE_SERVICE_BUS_NAME = "org.freedesktop.sssd.infopipe"
SSSD_INFOPIPE_USERS_SERVICE_NAME = "Users"
SSSD_INFOPIPE_USER_SERVICE_NAME = "Users.User"
DBUS_PROPERTIES_INTERFACE_NAME = 'org.freedesktop.DBus.Properties'


class Sssd:

    def __init__(self):
        """
        Docs: https://docs.pagure.org/sssd.sssd/design_pages/dbus_users_and_groups.html
        """
        # D-bus stuff:
        self._d_bus, \
        self._sssd_infopipe_proxy, \
        self._sssd_infopipe_iface = self._prep_dbus()

    def _prep_dbus(self) -> Tuple[Bus, proxies.ProxyObject, Interface]:
        # Global, system wide
        bus = SystemBus()
        log.debug("Using SystemBus for interface {}".format(SSSD_INFOPIPE_SERVICE_BUS_NAME))

        # Format the service name for bus and interface
        bus_name_parts = SSSD_INFOPIPE_SERVICE_BUS_NAME.split('.')
        object_path = "/{}/{}".format("/".join(bus_name_parts), SSSD_INFOPIPE_USERS_SERVICE_NAME)
        interface_name = "{}.{}".format(SSSD_INFOPIPE_SERVICE_BUS_NAME, SSSD_INFOPIPE_USERS_SERVICE_NAME)

        # Get the proxy and interface objects for given D-bus
        proxy = bus.get_object(SSSD_INFOPIPE_SERVICE_BUS_NAME, object_path)
        iface = Interface(proxy, dbus_interface=interface_name)

        return bus, proxy, iface

    def users(self) -> Generator:
        """
        Essentially do:
        dbus-send --system --print-reply  --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe/Users org.freedesktop.sssd.infopipe.Users.ListByName string:"*" uint32:"0"
        :return:
        """
        # Get list of all users, unlimited length
        users = self._sssd_infopipe_iface.ListByName('*', 0)
        interface_name = "{}.{}".format(SSSD_INFOPIPE_SERVICE_BUS_NAME, SSSD_INFOPIPE_USER_SERVICE_NAME)
        log.debug("User object interface: {}".format(interface_name))

        for user in users:
            log.debug("User object path: {}".format(user))
            proxy = self._d_bus.get_object(SSSD_INFOPIPE_SERVICE_BUS_NAME, user)
            iface = Interface(proxy, dbus_interface=DBUS_PROPERTIES_INTERFACE_NAME)
            user_data = iface.Get(interface_name, "uidNumber")

            yield int(user_data)
