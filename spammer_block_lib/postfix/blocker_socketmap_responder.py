import geoip2.database
import geoip2.errors
import ipaddress
import logging
from pathlib import Path
from typing import Optional, Union

from . import SocketmapResponder

logger = logging.getLogger(__name__)


class PostfixSocketmapResponder(SocketmapResponder):
    """
    Map a sending SMTP server's IP-address into its GeoIP ASN and return a
    Postfix access(5) action that prepends a ``Received-ASN:`` header.

    Socketmap responder altering mail headers
    -----------------------------------------
    A socketmap is a *read-only key -> value lookup table*
    (https://www.postfix.org/socketmap_table.5.html):
    the client sends ``name <space> key`` and the server
    answers ``OK <data>`` / ``NOTFOUND`` / ``TEMP`` / ``TIMEOUT`` / ``PERM``.
    The socketmap never sees the message body and has no facility to add,
    change or delete headers.

    *However*, Postfix evaluates lookup tables named in ``smtpd_*_restrictions``
    (e.g. ``check_client_access``) as **access(5)** maps, and an access(5) value
    may be an *action* rather than plain data. One such action (Postfix 2.1+) is::

        PREPEND headername: headervalue

    which prepends a header to the message (access.5 restriction: it must run
    before the message content is received, i.e. not in
    ``smtpd_end_of_data_restrictions``). So, consulted as a client-access map,
    this socketmap *can* cause a header to be added. The answer is therefore
    "yes, via the access-map / PREPEND mechanism".

    Postfix configuration (main.cf)::

        smtpd_client_restrictions =
            check_client_access socketmap:unix:/var/spool/postfix/private/asn_map:asn
            permit

    ``check_client_access`` probes the map with the client IP-address (and, for
    indexed tables, less-specific network forms such as ``1.2.3`` and the client
    hostname). We only act on keys that parse as a *complete* IP-address and
    answer ``NOTFOUND`` for everything else, so the header is prepended exactly
    once per connection.
    """

    # Headers injected via the access(5) PREPEND action.
    OK_HEADER_NAME: bytes = b"Received-ASN"
    SPAM_HEADER_NAME: bytes = b"Received-Spam-ASN"

    # "The Postfix socketmap client requires that replies are not longer than
    # 100000 characters" -- socketmap_table(5).
    MAX_REPLY_BYTES: int = 100000

    def __init__(self, *args, asn_database_path: Optional[str] = None, **kwargs) -> None:
        """
        Constructor.
        :param args: Common arguments
        :param asn_database_path: Path to GeoIP ASN database
        :param kwargs: Common keyword arguments
        """
        super().__init__(*args, **kwargs)
        logger.info("Using GeoIP2-ASN database: {}".format(asn_database_path))

        # geoip2.database.Reader is memory-mapped and thread-safe; open it once
        # for the lifetime of the daemon rather than per request.
        self._asn_reader = geoip2.database.Reader(asn_database_path)

    @staticmethod
    def _netstring_encode(payload: bytes) -> bytes:
        """
        Helper: Encode a Postfix netstring
        :param payload: Payload to encode
        :return: Bytes encoded netstring
        """
        # Socketmap replies are sent as one netstring: <length>:<payload>,
        return str(len(payload)).encode("ascii") + b":" + payload + b","

    def _reply(self, response_type: SocketmapResponder.ResponseType, data: bytes = b"") -> bytes:
        """
        Build a netstring-framed socketmap reply, ready to write to the socket.
        :param response_type: one of the ResponseType members (carries trailing space).
        :param data: payload following the response keyword.
        :return: netstring bytes.
        """
        payload = response_type.value + data
        if len(payload) > self.MAX_REPLY_BYTES:
            logger.error("Reply of {} bytes exceeds socketmap limit; "
                         "responding PERM".format(len(payload)))
            payload = SocketmapResponder.ResponseType.PERM.value + b"reply too long"

        return self._netstring_encode(payload)

    async def process_request(self, raw_req: bytes) -> bytes:
        """
        Docs: https://www.postfix.org/socketmap_table.5.html

        :param raw_req: request of the form ``name <space> key`` (netstring
                        framing already stripped by the StreamReader). When used
                        as a ``check_client_access`` map, ``key`` is the client
                        IP-address.
        :return: netstring-encoded reply written verbatim to the socket. On an
                 IP-address key with a known ASN this is::

                     OK PREPEND Received-ASN: AS<n> <org> (client <ip>)

                 otherwise ``NOTFOUND``.
        """

        # Split "name key" on the first space. The socketmap name is ignored:
        # this responder serves a single logical map.
        _name, _, key = raw_req.partition(b" ")
        if not key:
            return self._reply(SocketmapResponder.ResponseType.NOTFOUND)

        key_str = key.decode("ascii", errors="replace").strip()

        # check_client_access also probes hostnames and truncated network forms
        # ("1.2.3", "1.2"). Only act on a complete IP-address so the header is
        # prepended exactly once; everything else is a clean miss.
        try:
            ip = ipaddress.ip_address(key_str)
        except ValueError:
            logger.debug("Key {!r} is not a full IP-address; NOTFOUND".format(key_str))
            return self._reply(SocketmapResponder.ResponseType.NOTFOUND)

        try:
            asn_response = self._asn_reader.asn(str(ip))
        except geoip2.errors.AddressNotFoundError:
            logger.debug("No ASN for {}; NOTFOUND".format(ip))
            return self._reply(SocketmapResponder.ResponseType.NOTFOUND)
        except (ValueError, geoip2.errors.GeoIP2Error) as exc:
            logger.warning("ASN lookup failed for {}: {}".format(ip, exc))
            return self._reply(SocketmapResponder.ResponseType.TEMP, b"ASN lookup failed")

        asn = asn_response.autonomous_system_number
        org = asn_response.autonomous_system_organization or "unknown"
        header_value = self._build_header_value(ip, asn, org)

        # access(5) action that prepends a header to the message.
        action = b"PREPEND " + self.OK_HEADER_NAME + b": " + header_value
        logger.info("Client {} -> AS{} ({}); prepending {}".format(
            ip, asn, org, self.OK_HEADER_NAME.decode("ascii")))

        return self._reply(SocketmapResponder.ResponseType.OK, action)

    @staticmethod
    def _build_header_value(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                            asn: int, org: str) -> bytes:
        """
        Build a single, sanitized header value. access(5) PREPEND cannot prepend
        a multiline header, so collapse whitespace and strip CR/LF.
        """
        org_clean = " ".join(str(org).split())
        value = "AS{} {} (client {})".format(asn, org_clean, ip)
        value = value.replace("\r", " ").replace("\n", " ")

        return value.encode("ascii", errors="replace")
