from typing import Union
import requests
import re
import logging
from ..datasource_base import DatasourceBase


log = logging.getLogger(__name__)


class IPInfoIO_UI(DatasourceBase):
    """
    Class to implement AS-number queries via ipinfo.io.
    This method uses web GUI for data retrieval.
    NOTE: Number of queries from sinlge IPv4-address are heavily limited to 5 per day.
    """

    ASN_QUERY_URL = "https://ipinfo.io/widget/AS{0}"
    QUERY_REFERER = r"https://ipinfo.io/"

    def __init__(self):
        self._session = None

    def _get_session(self) -> requests.Session:
        if self._session:
            return self._session

        self._session = requests.Session()

        return self._session

    def lookup(self, as_number: int) -> Union[None, dict]:
        url = self.ASN_QUERY_URL.format(as_number)
        log.info("IPinfo.io UI: Query AS{0} via '{1}'".format(as_number, url))
        sess = self._get_session()
        headers = {
            "Referer": self.QUERY_REFERER
        }
        response = sess.get(url, headers=headers)
        if response.status_code != 200:
            log.warning("IPinfo.io query returned HTTP/{0}!".format(response.status_code))
            return None

        data = response.json()
        """
        'allocated': '2000-08-23',
        'asn': 'AS17358',
        'country': 'CA',
        'domain': 'atsound.com',
        'downstreams': ['14265'],
        'name': 'eToll, Inc.',
        'num_ips': 29440,
        'peers': ['577', '15290'],
        'prefixes': [{'country': 'CA',
        """
        data["nets"] = []
        for prefix in data["prefixes"]:
            """ Example dict received from web UI:
            {'country': 'TR',
               'domain': 'gridtelekom.com',
               'id': 'TR-GRID-20140417',
               'name': 'Grid Bilisim Teknolojileri A.S.',
               'netblock': '185.54.88.0/24',
               'size': '256',
               'status': 'ASSIGNED PA'}
            """
            net = {
                'description': prefix['name'],
                'cidr': prefix['netblock'],
            }
            data["nets"].append(net)

        return data
