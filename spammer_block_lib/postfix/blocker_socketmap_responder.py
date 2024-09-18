from typing import Optional
import logging

from . import SocketmapResponder

logger = logging.getLogger(__name__)


class PostfixSocketmapResponder(SocketmapResponder):

    async def process_request(self, raw_req: bytes) -> tuple[SocketmapResponder.ResponseType, Optional[bytes]]:
        """
        Docs: https://www.postfix.org/socketmap_table.5.html
        "The Postfix socketmap client requires that replies are not longer than 100000 characters"
        :param raw_req: The request has the following form:
                        name <space> key
                              Search the named socketmap for the specified key.
        :return:
        """

        # Not found
        self.RESPONSE_NOTFOUND

        # The requested data was found.
        b'OK secure match='
        self.RESPONSE_OK

        #
        self.RESPONSE_TEMP

        #
        self.RESPONSE_TIMEOUT

        #
        self.RESPONSE_PERM

        raise NotImplemented("Yet!")
