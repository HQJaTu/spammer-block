#!/usr/bin/env python3

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
from dbus import (SessionBus, service)
from spammer_block_lib import SpamcopReporter
import logging

log = logging.getLogger(__name__)

# Docs:
# https://dbus.freedesktop.org/doc/dbus-tutorial.html#bus-names
SPAM_REPORTER_SERVICE_BUS_NAME = "com.spamcop.Reporter"


class SpamReporterService(service.Object):
    SPAM_REPORTER_SERVICE = SPAM_REPORTER_SERVICE_BUS_NAME.split('.')
    OPATH = "/" + "/".join(SPAM_REPORTER_SERVICE)

    def __init__(self, send_from: str, send_to: Union[str, list], host: str = "127.0.0.1"):
        bus = SessionBus()
        bus.request_name(SPAM_REPORTER_SERVICE_BUS_NAME)
        bus_name = service.BusName(SPAM_REPORTER_SERVICE_BUS_NAME, bus=bus)
        service.Object.__init__(self, bus_name, self.OPATH)

        self.from_address = send_from
        self.spamcop_report_address = send_to
        self.smtpd_host = host

    @service.method(dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="s")
    def Ping(self):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        :return:
        """
        log.warning("ping received")

        return "pong"

    @service.method(dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME,
                    in_signature="s", out_signature="s")
    def ReportFile(self, filename: str):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        :return:
        """
        reporter = SpamcopReporter(
            send_from=self.from_address,
            send_to=self.spamcop_report_address,
            host=self.smtpd_host
        )
        log.info("Reporting file: {}".format(filename))
        if not os.path.exists(filename):
            log.error("Input file {} doesn't exist!".format(filename))
            raise ValueError("Bad input file!")

        try:
            reporter.report_files([filename])
        except Exception:
            log.exception("Reporting failed!")

        log.info("Done reporting")

        return "ok"
