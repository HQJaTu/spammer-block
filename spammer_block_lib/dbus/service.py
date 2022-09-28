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

import os
from typing import Union
from dbus import (SessionBus, SystemBus, service, mainloop)
from pwd import getpwuid
from spammer_block_lib import reporter as spam_reporters
import logging

log = logging.getLogger(__name__)

# Docs:
# https://dbus.freedesktop.org/doc/dbus-tutorial.html#bus-names
SPAM_REPORTER_SERVICE_BUS_NAME = "fi.hqcodeshop.SpamReporter"


class SpamReporterService(service.Object):
    SPAM_REPORTER_SERVICE = SPAM_REPORTER_SERVICE_BUS_NAME.split('.')
    OPATH = "/" + "/".join(SPAM_REPORTER_SERVICE)

    def __init__(self, use_system_bus: bool,
                 loop: mainloop.NativeMainLoop,
                 config: dict):
        # Which bus to use for publishing?
        self._use_system_bus = use_system_bus
        if use_system_bus:
            # Global, system wide
            bus = SystemBus(mainloop=loop)
            log.debug("Using SystemBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))
        else:
            # User's own
            bus = SessionBus(mainloop=loop)
            log.debug("Using SessionBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))

        bus.request_name(SPAM_REPORTER_SERVICE_BUS_NAME)
        bus_name = service.BusName(SPAM_REPORTER_SERVICE_BUS_NAME, bus=bus)
        service.Object.__init__(self, bus_name, self.OPATH)

        self._loop = loop
        self.config = config

    # noinspection PyPep8Naming
    @service.method(dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="s")
    def Ping(self):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        Source code:
        https://github.com/freedesktop/dbus-python/blob/master/dbus/service.py
        :return: str
        """
        log.info("ping received")

        # Get a BusConnection-object of this call and query for more details.
        if self.connection._bus_type == 0:
            bus_type = "session"
        elif self.connection._bus_type == 1:
            bus_type = "system"
        else:
            bus_type = "unknown"
        unix_user_id = self.connection.get_unix_user(SPAM_REPORTER_SERVICE_BUS_NAME)

        greeting = ""
        # Get details of user ID making the request
        unix_user_passwd_record = getpwuid(unix_user_id)
        if unix_user_passwd_record:
            user = unix_user_passwd_record.pw_name
            if unix_user_passwd_record.pw_gecos:
                gecos = unix_user_passwd_record.pw_gecos.split(',')
                if gecos[0]:
                    user = gecos[0]
            greeting = "Hi {}".format(user)
        else:
            greeting = "Hi"
        greeting = "{} in {}-bus! pong".format(greeting, bus_type)

        return greeting

    # noinspection PyPep8Naming
    @service.method(dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME,
                    in_signature="s", out_signature="s")
    def ReportFile(self, filename: str):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        :param filename, str, filename of spam mail in RFC822 format
        :return: str, constant "ok"
        """
        if self.config['Reporter']['spamcop_report_address']:
            reporter = spam_reporters.SpamcopReporter(send_from=self.config['Reporter']['from_address'],
                                                      send_to=self.config['Reporter']['spamcop_report_address'],
                                                      host=self.config['Reporter']['smtpd_address'])
            log.info("D-Bus service reporting file: {} to SpamCop".format(filename))
        elif self.config['Reporter']['mock_report_address']:
            reporter = spam_reporters.MockReporter(send_from=self.config['Reporter']['from_address'],
                                                   send_to=self.config['Reporter']['mock_report_address'],
                                                   host=self.config['Reporter']['smtpd_address'])
            log.info("D-Bus service reporting file: {} to mock service".format(filename))
        else:
            raise RuntimeError("Aow come on! Need a back-end to work with.")

        if not os.path.exists(filename):
            log.error("Input file {} doesn't exist!".format(filename))

            return "Bad input file!"

        try:
            reporter.report_files([filename])
        except Exception:
            log.exception("Reporting failed!")

        log.info("Done reporting")

        return "ok"
