# SPDX-License-Identifier: GPL-2.0

from typing import Optional, Tuple, Union
import logging
import maxminddb
from ..datasource_base import DatasourceBase

log = logging.getLogger(__name__)


class Geoip2ASN(DatasourceBase):
    """
    AS-number datasource backed by a local MaxMind GeoLite2-ASN.mmdb file.

    Unlike the network-based datasources (ipinfo.io, RADb) this needs no remote
    queries and has no rate limits -- everything is answered from the local
    memory-mapped database. The file maps networks to an ASN, which supports two
    operations:

    * ``asn_for_ip(ip)`` -- the IP -> ASN lookup used by the Postfix socketmap
      responder. One O(1) database read.
    * ``lookup(asn)`` -- the ASN -> networks lookup required by the
      DatasourceBase contract (consumed by SpammerBlock / blocker.py). The mmdb
      is keyed by network, so this scans the whole database collecting every
      network whose ASN matches. That is O(database size) -- fine for the
      occasional CLI query, which is why the responder uses asn_for_ip() instead.
    """

    # Record keys used by GeoLite2-ASN.
    _ASN_KEY = "autonomous_system_number"
    _ORG_KEY = "autonomous_system_organization"

    def __init__(self, ip: str = None, db_file: str = None):
        """
        :param ip: optional context IP (kept for parity with the other
                   datasources; not required, asn_for_ip() takes the IP directly).
        :param db_file: path to GeoLite2-ASN.mmdb. Required.
        """
        if not db_file:
            raise ValueError("Geoip2ASN requires a GeoLite2-ASN.mmdb path (db_file).")
        self._ip = ip
        self._db_file = db_file
        # Memory-mapped and safe to reuse across lookups for the process lifetime.
        self._reader = maxminddb.open_database(db_file)

    def asn_for_ip(self, ip) -> Optional[Tuple[int, str]]:
        """
        Look up the ASN owning an IP-address.
        :param ip: IP-address (str or ipaddress object).
        :return: (asn_number, organization) or None when the IP is not in the DB.
        """
        record = self._reader.get(str(ip))
        if not record:
            return None
        asn = record.get(self._ASN_KEY)
        if asn is None:
            return None
        return asn, record.get(self._ORG_KEY) or "unknown"

    def lookup(self, asn: int) -> Union[None, dict]:
        """
        Collect every network assigned to an AS-number.
        :param asn: AS-number to query.
        :return: dict with 'query'/'nets' (matching the other datasources), or
                 None when the ASN has no networks in the database.
        """
        log.info("GeoIP2-ASN: Query AS{0}".format(asn))

        nets = []
        for network, record in self._reader:
            if record and record.get(self._ASN_KEY) == asn:
                nets.append({
                    'cidr': str(network),
                    'description': record.get(self._ORG_KEY) or '',
                })

        if not nets:
            log.debug("GeoIP2-ASN: no networks found for AS{}".format(asn))
            return None

        return {
            'query': 'AS{}'.format(asn),
            'nets': nets,
        }

    def close(self) -> None:
        self._reader.close()

    def __enter__(self) -> "Geoip2ASN":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
