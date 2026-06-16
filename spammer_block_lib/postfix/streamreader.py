import ssl


class NetstringException(Exception):
    """Base class for all netstring parsing signals/errors."""


class WantRead(NetstringException):
    """Raised when more input is required to continue parsing.

    Not an error: the caller should feed() more bytes and retry read()."""


class ParseError(NetstringException):
    """Base class for fatal netstring protocol violations."""


class BadLength(ParseError):
    """The netstring length prefix is malformed (non-digit, empty, leading zero)."""


class TooLong(ParseError):
    """The declared netstring length exceeds the configured maximum."""


class InappropriateParserState(NetstringException):
    """next_string() called while the previous fetcher is not yet exhausted."""


# Parser states for SingleNetstringFetcher.
_STATE_LENGTH = 0   # reading ASCII length digits up to ':'
_STATE_PAYLOAD = 1  # reading <length> payload bytes
_STATE_COMMA = 2    # expecting the terminating ','
_STATE_DONE = 3     # netstring fully consumed


class SingleNetstringFetcher:
    """Incremental decoder for a single netstring (``<length>:<payload>,``).

    read() pulls bytes from a shared ssl.MemoryBIO and returns:
      * a non-empty bytes chunk of the payload, as it becomes available,
      * b'' exactly once, when the whole netstring (including the trailing
        comma) has been consumed,
    or raises:
      * WantRead   - the BIO is momentarily empty; feed() more and retry,
      * ParseError - the input is not a well-formed netstring.

    State persists across calls, so a netstring may be delivered in arbitrarily
    fragmented reads."""

    def __init__(self, incoming: ssl.MemoryBIO, maxlen: int = -1):
        self._incoming = incoming
        self._maxlen = maxlen
        self._state = _STATE_LENGTH
        self._len_buf = b""
        self._length = 0
        self._got = 0

    def done(self) -> bool:
        return self._state == _STATE_DONE

    def pending(self) -> bool:
        """True while a netstring is being parsed but is not yet complete."""
        return self._state != _STATE_DONE

    def _read_length(self) -> None:
        """Consume length digits up to ':'. Raises WantRead/BadLength/TooLong."""
        while True:
            byte = self._incoming.read(1)
            if not byte:
                raise WantRead()
            if byte == b":":
                if not self._len_buf:
                    raise BadLength("empty netstring length prefix")
                self._length = int(self._len_buf)
                self._got = 0
                self._state = _STATE_COMMA if self._length == 0 else _STATE_PAYLOAD
                return
            if not byte.isdigit():
                raise BadLength("non-digit in netstring length: {!r}".format(byte))
            # Reject leading zeros ("0" alone is valid, "01" is not).
            if self._len_buf == b"0":
                raise BadLength("leading zero in netstring length")
            self._len_buf += byte
            if self._maxlen >= 0 and int(self._len_buf) > self._maxlen:
                raise TooLong("netstring length {} exceeds maximum {}".format(
                    int(self._len_buf), self._maxlen))

    def read(self) -> bytes:
        while True:
            if self._state == _STATE_DONE:
                return b""

            if self._state == _STATE_LENGTH:
                self._read_length()
                continue  # state advanced to PAYLOAD or COMMA

            if self._state == _STATE_PAYLOAD:
                chunk = self._incoming.read(self._length - self._got)
                if not chunk:
                    raise WantRead()
                self._got += len(chunk)
                if self._got >= self._length:
                    self._state = _STATE_COMMA
                return chunk

            # _STATE_COMMA
            byte = self._incoming.read(1)
            if not byte:
                raise WantRead()
            if byte != b",":
                raise ParseError("netstring not terminated by ',', got {!r}".format(byte))
            self._state = _STATE_DONE
            return b""


class StreamReader:
    """ Async Netstring protocol decoder with interface
    alike to ssl.SSLObject BIO interface.

    next_string() method returns SingleNetstringFetcher class which
    fetches parts of netstring.

    SingleNestringFetcher.read() returns b'' in case of string end or raises
    WantRead exception when StreamReader needs to be filled with additional
    data. Parsing errors signalized with exceptions subclassing ParseError"""

    def __init__(self, maxlen: int = -1):
        """ Creates StreamReader instance.

        Params:

        maxlen - maximal allowed netstring length.
        """
        self._maxlen = maxlen
        self._incoming = ssl.MemoryBIO()
        self._fetcher = None

    def pending(self) -> bool:
        return self._fetcher is not None and self._fetcher.pending()

    def feed(self, data):
        self._incoming.write(data)

    def next_string(self):
        if self._fetcher is not None and not self._fetcher.done():
            raise InappropriateParserState("next_string() invoked while "
                                           "previous fetcher is not exhausted")
        self._fetcher = SingleNetstringFetcher(self._incoming, self._maxlen)

        return self._fetcher
