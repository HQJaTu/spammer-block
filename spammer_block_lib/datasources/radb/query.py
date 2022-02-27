from typing import Union
from ipwhois import (
    Net as IPWhoisNet,
    ASNOriginLookupError
)
from ipwhois.asn import ASNOrigin as IPWhoisASNOrigin
from ..datasource_base import DatasourceBase
import logging

log = logging.getLogger(__name__)


class RADb(DatasourceBase):
    """
    Class to implement AS-number queries via RADb (https://www.radb.net/query).
    NOTE: The information retrieved isn't very accurate. Number of networks in AS-number differes a lot from reality.
    NOTE 2: There is no restrictions on how many queries can be made.
    """

    def __init__(self, ip: str):
        self._ip = ip

    def lookup(self, asn: int) -> Union[None, dict]:
        log.info("RADb: Query AS{0}".format(asn))

        net = IPWhoisNet(self._ip)
        log.debug("Query HTTP from RADb")
        # Original: https://github.com/secynic/ipwhois
        asn_query = IPWhoisASNOrigin(net)
        methods = ['http']

        try:
            asn_result = asn_query.lookup(asn='AS{}'.format(asn), asn_methods=methods)
        except ASNOriginLookupError:
            log.debug("RADb failed to query AS{}!".format(asn))
            return None

        return asn_result
