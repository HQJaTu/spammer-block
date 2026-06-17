# SPDX-License-Identifier: GPL-2.0

"""
LMDB-backed ASN reputation database.

Two-tier model
--------------
* ``asn``  sub-db: an ASN-wide default verdict (pass / spam).
* ``net4`` / ``net6`` sub-dbs: per-network *overrides* that are more specific
  than the ASN default -- e.g. a single allowed /32 inside an otherwise-spam
  ASN, or a blocked /24 inside an otherwise-clean one. Overrides can flip the
  verdict either way.

Resolution order for a client IP (and its ASN, supplied by the caller from
GeoIP): most-specific network override  ->  ASN default  ->  unknown.

Longest-prefix match
--------------------
Rather than the fragile "key by broadcast address + single range step" trick
(which silently misses a containing network when a tighter, non-containing one
sorts in between), we probe candidate networks from the longest possible prefix
down to the shortest and take the first hit. Because any two CIDRs are either
disjoint or nested, the first hit (longest prefix) is always the most specific
match. Each probe is one O(1) LMDB lookup; at most 33 probes for IPv4 and 129
for IPv6 -- microseconds, and correct by construction.

Concurrency
-----------
LMDB gives multi-reader / single-writer MVCC across processes. The CLI is the
writer; the responder daemon is a reader. Each lookup uses a short read
transaction, so committed edits are visible immediately with no reload.
"""

import ipaddress
import json
import lmdb
import logging
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional, Union

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Named sub-databases inside the single LMDB environment.
_ASN_DB = b"asn"
_NET_DB = {4: b"net4", 6: b"net6"}
_META_DB = b"meta"
_ALL_DBS = (_ASN_DB, _NET_DB[4], _NET_DB[6], _META_DB)

SCHEMA_VERSION = 1
# LMDB needs an upper bound on the memory map (== max file size). It is virtual
# address space, not preallocated disk, so a generous default is cheap.
DEFAULT_MAP_SIZE = 1 << 30  # 1 GiB


def _now() -> str:
    """Current UTC time as a second-resolution ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _dumps(record: dict) -> bytes:
    return json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Verdict:
    """
    Allowed verdict values (kept as plain str constants for easy I/O).
    """
    PASS = "pass"
    SPAM = "spam"

    _ALL = (PASS, SPAM)

    @classmethod
    def validate(cls, value: str) -> str:
        if value not in cls._ALL:
            raise ValueError("Invalid verdict {!r}; expected one of {}".format(
                value, ", ".join(cls._ALL)))
        return value


class Source:
    """
    Where a resolved verdict came from.
    """
    OVERRIDE = "override"
    ASN = "asn"
    DEFAULT = "default"


@dataclass(frozen=True)
class AsnRecord:
    """
    AS number record.
    A spammer or a known good.
    """
    asn: int
    verdict: str
    org: Optional[str]
    comment: Optional[str]
    updated_at: str


@dataclass(frozen=True)
class OverrideRecord:
    """
    An override for ASN record.
    Practically, this is an allow IP-address in a spam ASN.
    """
    cidr: str
    family: int
    verdict: str
    asn: Optional[int]
    comment: Optional[str]
    updated_at: str

    @property
    def prefixlen(self) -> int:
        return ipaddress.ip_network(self.cidr).prefixlen


@dataclass(frozen=True)
class Resolution:
    """
    Outcome of resolve(): verdict is None when no rule matched.
    """
    verdict: Optional[str]
    source: str
    matched: Optional[str]  # the override CIDR, "AS<n>", or None
    asn: Optional[int] = None

    @property
    def is_known(self) -> bool:
        return self.verdict is not None


class ReputationDb:
    """
    Reputation store over an LMDB environment.
    """

    def __init__(self, path: str, *, map_size: int = DEFAULT_MAP_SIZE,
                 readonly: bool = False) -> None:
        """
        :param path: LMDB environment path (a directory is created).
        :param map_size: maximum map / file size in bytes.
        :param readonly: open read-only (for the responder daemon). The DB must
                         already exist; missing sub-databases are tolerated and
                         treated as empty.
        """
        self._path = str(path)
        self._readonly = readonly
        self._env = lmdb.open(self._path, max_dbs=len(_ALL_DBS),
                              map_size=map_size, readonly=readonly,
                              create=not readonly, subdir=True,
                              lock=True)

        self._asn = self._open_db(_ASN_DB)
        self._net = {4: self._open_db(_NET_DB[4]), 6: self._open_db(_NET_DB[6])}
        self._meta = self._open_db(_META_DB)

        if not readonly:
            self._ensure_schema()

    def _open_db(self, name: bytes):
        """
        Open (and, when writable, create) a named sub-database.
        :param name: sub-database name.
        :return: sub-database object.
        """
        try:
            return self._env.open_db(name, create=not self._readonly)
        except lmdb.NotFoundError:
            # Read-only open against a DB that has never held this sub-db yet.
            logger.debug("Sub-database %r absent (read-only); treating as empty.", name)
            return None

    def _ensure_schema(self) -> None:
        with self._env.begin(write=True, db=self._meta) as txn:
            if txn.get(b"schema_version") is None:
                txn.put(b"schema_version", str(SCHEMA_VERSION).encode("ascii"))

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._env.close()

    def __enter__(self) -> "ReputationDb":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def path(self) -> str:
        return self._path

    # -- ASN tier ----------------------------------------------------------

    @staticmethod
    def _asn_key(asn: int) -> bytes:
        """
        Get ASN key
        :param asn: ASN to get key.
        :return: bytes
        """
        if not 0 <= asn <= 0xFFFFFFFF:
            raise ValueError("ASN out of range (0..4294967295): {}".format(asn))
        return struct.pack(">I", asn)

    @staticmethod
    def _decode_asn(asn: int, raw: bytes) -> AsnRecord:
        """
        Decode an ASN.
        :param asn: ASN to decode.
        :param raw: Raw bytes
        :return: Asn record.
        """
        d = json.loads(raw)
        return AsnRecord(asn=asn, verdict=d["v"], org=d.get("org"),
                         comment=d.get("c"), updated_at=d["ts"])

    def set_asn(self, asn: int, verdict: str, org: Optional[str] = None,
                comment: Optional[str] = None, *, updated_at: Optional[str] = None) -> None:
        """
        Create or replace the default verdict for an ASN.
        :param asn: ASN to set.
        :param verdict: Verdict to set.
        :param org: Organization name.
        :param comment: Comment to set.
        :param updated_at: Updated timestamp.
        """
        verdict = Verdict.validate(verdict)
        record = {"v": verdict, "org": org, "c": comment, "ts": updated_at or _now()}
        with self._env.begin(write=True, db=self._asn) as txn:
            txn.put(self._asn_key(asn), _dumps(record))

    def get_asn(self, asn: int) -> Optional[AsnRecord]:
        """
        Get ASN
        :param asn: ASN to get.
        :return: ASN record if found
        """
        if self._asn is None:
            return None
        with self._env.begin(db=self._asn) as txn:
            raw = txn.get(self._asn_key(asn))
        return self._decode_asn(asn, raw) if raw is not None else None

    def delete_asn(self, asn: int) -> bool:
        """
        Remove an ASN default
        :param asn: ASN to remove.
        :return: True if the row was deleted.
        """
        with self._env.begin(write=True, db=self._asn) as txn:
            return txn.delete(self._asn_key(asn))

    def iter_asns(self) -> Iterator[AsnRecord]:
        """
        All ASN defaults, ordered by ASN ascending.
        """
        if self._asn is None:
            return []
        out = []
        with self._env.begin(db=self._asn) as txn:
            for key, raw in txn.cursor():
                out.append(self._decode_asn(struct.unpack(">I", key)[0], raw))
        return out

    # -- override tier -----------------------------------------------------

    @staticmethod
    def _parse_net(cidr: Union[str, IPNetwork]) -> IPNetwork:
        """
        Parse a CIDR network
        :param cidr: CIDR network
        :return: Network
        """
        if isinstance(cidr, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return cidr
        return ipaddress.ip_network(cidr, strict=False)

    @staticmethod
    def _net_key(net: IPNetwork) -> bytes:
        """
        Get a key of network
        :param net: Network to get key for
        :return: The key
        """

        # masked network address (4 or 16 bytes) + prefix length (1 byte)
        return net.network_address.packed + bytes([net.prefixlen])

    @staticmethod
    def _decode_override(net: IPNetwork, raw: bytes) -> OverrideRecord:
        """
        Decode an override.
        :param net: Network to decode
        :param raw: Raw bytes to decode
        :return: An OverrideRecord object.
        """
        d = json.loads(raw)
        return OverrideRecord(cidr=d.get("cidr") or str(net), family=net.version,
                              verdict=d["v"], asn=d.get("asn"),
                              comment=d.get("c"), updated_at=d["ts"])

    def set_override(self, cidr: Union[str, IPNetwork], verdict: str,
                     asn: Optional[int] = None, comment: Optional[str] = None,
                     *, updated_at: Optional[str] = None) -> str:
        """
        Create or replace a per-network override. A bare IP is stored as a host
        route (/32 or /128). Returns the normalised CIDR string.
        :param cidr: CIDR to set
        :param verdict: Verdict to set
        :param asn: ASN to set
        :param comment: Comment to set
        :param updated_at: Updated timestamp
        :return: CIDR string
        """
        net = self._parse_net(cidr)
        verdict = Verdict.validate(verdict)
        record = {"v": verdict, "asn": asn, "c": comment,
                  "cidr": str(net), "ts": updated_at or _now()}
        with self._env.begin(write=True, db=self._net[net.version]) as txn:
            txn.put(self._net_key(net), _dumps(record))

        return str(net)

    def get_override(self, cidr: Union[str, IPNetwork]) -> Optional[OverrideRecord]:
        """
        Get an override.
        :param cidr: CIDR to get
        :return: Record of override, if any found
        """
        net = self._parse_net(cidr)
        db = self._net.get(net.version)
        if db is None:
            return None
        with self._env.begin(db=db) as txn:
            raw = txn.get(self._net_key(net))
        return self._decode_override(net, raw) if raw is not None else None

    def delete_override(self, cidr: Union[str, IPNetwork]) -> bool:
        """
        Delete an override.
        :param cidr: CIDR to override
        :return: bool, True if a row was deleted.
        """
        net = self._parse_net(cidr)
        db = self._net.get(net.version)
        if db is None:
            return False

        with self._env.begin(write=True, db=db) as txn:
            return txn.delete(self._net_key(net))

    def iter_overrides(self, family: Optional[int] = None) -> Iterator[OverrideRecord]:
        """
        All overrides (optionally one family), ordered by network then prefix.
        """
        families = (family,) if family in (4, 6) else (4, 6)
        out = []
        for fam in families:
            db = self._net.get(fam)
            if db is None:
                continue
            addr_cls = ipaddress.IPv4Address if fam == 4 else ipaddress.IPv6Address
            with self._env.begin(db=db) as txn:
                for key, raw in txn.cursor():
                    net_addr = addr_cls(key[:-1])
                    plen = key[-1]
                    net = ipaddress.ip_network("{}/{}".format(net_addr, plen))
                    out.append(self._decode_override(net, raw))

        return out

    # -- resolution --------------------------------------------------------

    @staticmethod
    def _mask_int(ip_int: int, prefixlen: int, maxbits: int) -> int:
        if prefixlen <= 0:
            return 0
        shift = maxbits - prefixlen

        return (ip_int >> shift) << shift

    def _lookup_override(self, ip: IPAddress) -> Optional[OverrideRecord]:
        db = self._net.get(ip.version)
        if db is None:
            return None
        maxbits = ip.max_prefixlen
        ip_int = int(ip)
        addr_cls = ipaddress.IPv4Address if ip.version == 4 else ipaddress.IPv6Address
        with self._env.begin(db=db) as txn:
            # Probe longest prefix first; first hit is the most specific match.
            for prefixlen in range(maxbits, -1, -1):
                net_addr = addr_cls(self._mask_int(ip_int, prefixlen, maxbits))
                raw = txn.get(net_addr.packed + bytes([prefixlen]))
                if raw is not None:
                    net = ipaddress.ip_network("{}/{}".format(net_addr, prefixlen))
                    return self._decode_override(net, raw)

        return None

    def resolve(self, ip: Union[str, IPAddress], asn: Optional[int] = None) -> Resolution:
        """
        Resolve the verdict for a client IP.

        :param ip: the client IP-address.
        :param asn: its ASN (from GeoIP), used for the ASN-default fallback.
        :return: Resolution; ``verdict is None`` (Source.DEFAULT) when nothing
                 in the database matches.
        """
        if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = ipaddress.ip_address(ip)

        override = self._lookup_override(ip)
        if override is not None:
            return Resolution(verdict=override.verdict, source=Source.OVERRIDE,
                              matched=override.cidr, asn=override.asn)

        if asn is not None:
            asn_rec = self.get_asn(asn)
            if asn_rec is not None:
                return Resolution(verdict=asn_rec.verdict, source=Source.ASN,
                                  matched="AS{}".format(asn), asn=asn)

        return Resolution(verdict=None, source=Source.DEFAULT, matched=None, asn=asn)
