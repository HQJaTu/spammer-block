import ipaddress
import lmdb
import logging
from pathlib import Path
from typing import Optional, Union

from . import SocketmapResponder
from ..datasources import Geoip2ASN
from ..reputation import ReputationDb, Verdict

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

    def __init__(self, *args, asn_database_path: Optional[str] = None,
                 reputation_db_path: Optional[str] = None, **kwargs) -> None:
        """
        Constructor.
        :param args: Common arguments
        :param asn_database_path: Path to GeoIP ASN database
        :param reputation_db_path: Path to the LMDB reputation database, or None.
                                   When None, reputation is skipped and every
                                   resolvable sender is treated as pass
                                   (informational OK_HEADER_NAME only).
        :param kwargs: Common keyword arguments
        """
        super().__init__(*args, **kwargs)
        logger.info("Using GeoIP2-ASN database: {}".format(asn_database_path))

        # The responder always resolves IP -> ASN from the local GeoLite2-ASN
        # database, via the Geoip2ASN datasource. It is memory-mapped, so open it
        # once for the lifetime of the daemon rather than per request.
        self._asn_datasource = Geoip2ASN(db_file=asn_database_path)

        # The reputation database is opened read-only: this daemon never writes
        # it (the spammer-reputation-db CLI is the writer). Each resolve() runs a
        # short read transaction, so CLI edits are picked up without a restart.
        self._rep_db: Optional[ReputationDb] = None
        if reputation_db_path:
            try:
                self._rep_db = ReputationDb(reputation_db_path, readonly=True)
            except lmdb.Error as exc:
                raise FileNotFoundError(
                    "Cannot open reputation database {!r} read-only: {}. Create it first "
                    "with the spammer-reputation-db CLI.".format(reputation_db_path, exc))
            logger.info("Using reputation database: {}".format(reputation_db_path))
        else:
            logger.info("No reputation database configured; treating all senders as pass.")

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

        # Go query the ASN for the IP-address
        try:
            asn_lookup = self._asn_datasource.asn_for_ip(ip)
        except Exception as exc:
            # A single failed lookup must not take the daemon down; let Postfix retry.
            logger.warning("ASN lookup failed for {}: {}".format(ip, exc))
            return self._reply(SocketmapResponder.ResponseType.TEMP, b"ASN lookup failed")
        if asn_lookup is None:
            logger.debug("No ASN for {}; NOTFOUND".format(ip))
            return self._reply(SocketmapResponder.ResponseType.NOTFOUND)

        asn, org = asn_lookup

        # Resolve the reputation verdict. Only an explicit 'spam' rule (ASN
        # default or network override) flags the sender; pass and unknown (no
        # rule) both resolve to pass -- the configured unknown-ASN policy.
        verdict = Verdict.PASS
        matched = None
        if self._rep_db is not None:
            resolution = self._rep_db.resolve(ip, asn)
            matched = resolution.matched
            if resolution.verdict == Verdict.SPAM:
                verdict = Verdict.SPAM

        header_name = self.SPAM_HEADER_NAME if verdict == Verdict.SPAM else self.OK_HEADER_NAME
        header_value = self._build_header_value(ip, asn, org, verdict, matched)

        # access(5) action that prepends a header to the message.
        action = b"PREPEND " + header_name + b": " + header_value
        logger.info("Client {} -> AS{} ({}); verdict={} rule={}; prepending {}".format(
            ip, asn, org, verdict, matched, header_name.decode("ascii")))

        return self._reply(SocketmapResponder.ResponseType.OK, action)

    @staticmethod
    def _build_header_value(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                            asn: int, org: str, verdict: str,
                            matched: Optional[str]) -> bytes:
        """
        Build a single, sanitized header value. access(5) PREPEND cannot prepend
        a multiline header, so collapse whitespace and strip CR/LF.
        """
        org_clean = " ".join(str(org).split())
        value = "AS{} {}; client={}; verdict={}".format(asn, org_clean, ip, verdict)
        if matched:
            value += "; rule={}".format(matched)
        value = value.replace("\r", " ").replace("\n", " ")

        return value.encode("ascii", errors="replace")
