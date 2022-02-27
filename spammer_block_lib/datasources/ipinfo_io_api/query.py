from typing import Union
from ipwhois import (
    IPWhois,
    Net as IPWhoisNet,
    exceptions as IPWhoisExceptions
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ..datasource_base import DatasourceBase
import logging

log = logging.getLogger(__name__)


class IPInfoIO(DatasourceBase):
    """
    Class to implement AS-number queries via ipinfo.io.
    This method uses API for data retrieval.
    NOTE: Number of anonymous queries from sinlge IPv4-address are heavily limited to 5 per day.
    NOTE 2: If using API-key, but non-paid one, same restriction applies.
    """

    def __init__(self, ip: str, token: str = None):
        self._ip = ip
        self.ipinfo_token = token

    def lookup(self, asn: int) -> Union[None, dict]:
        log.info("IPinfo.io: Query AS{0}".format(asn))

        net = IPWhoisNet(self._ip)
        if hasattr(IPWhoisASNOrigin, 'ASN_SOURCE_HTTP_IPINFO'):
            methods = [IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]
        else:
            methods = [IPWhoisASNOrigin.ASN_SOURCE_WHOIS, IPWhoisASNOrigin.ASN_SOURCE_HTTP_IPINFO]

        log.debug("Query HTTP from IPinfo.io")
        if not self.ipinfo_token:
            log.error("Attempt to use ipinfo.io API without token")
        # See extended version: https://github.com/HQJaTu/ipwhois/tree/ipinfo.io
        asn_query = IPWhoisASNOrigin(net, token=self.ipinfo_token)

        try:
            asn_result = asn_query.lookup(asn='AS{}'.format(asn), asn_methods=methods)
        except IPWhoisExceptions.ASNOriginLookupError:
            log.exception("Failed to query via IPinfo.io API")
            raise

        return asn_result
