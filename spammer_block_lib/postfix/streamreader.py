import ssl


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
