import os
import sys
import signal
import asyncio
import socket
from codecs import StreamWriter
from functools import partial
from abc import ABC, abstractmethod
from queue import Queue
import enum
import logging

from .streamreader import StreamReader

logger = logging.getLogger(__name__)


class SocketmapResponder(ABC):
    """
    See: https://github.com/Snawoot/postfix-mta-sts-resolver/blob/master/postfix_mta_sts_resolver/responder.py
    """

    # List of valid Postmap responses:
    class ResponseType(enum.Enum):
        NOTFOUND = b'NOTFOUND '  # The requested data was not found. No further data allowed.
        OK = b'OK '  # The requested data was found. Payload required.
        TEMP = b'TEMP '  # The request failed. The reason, if non-empty, is descriptive text.
        TIMEOUT = b'TIMEOUT '  # The request failed. The reason, if non-empty, is descriptive text.
        PERM = b'PERM '  # The request failed. The reason, if non-empty, is descriptive text.

    # REQUEST_ENCODING = 'utf-8'
    CHUNK_SIZE_BYTES: int = 4096
    QUEUE_SIZE_BYTES: int = 128
    REQUEST_LIMIT_BYTES: int = 1024

    def __init__(self, loop: asyncio.AbstractEventLoop,
                 unix_socket_path: str = None, socket_mode: int = None,
                 tcp_socket: tuple[str, int] = None, reuse_port: bool = False,
                 shutdown_timeout: int = 1):

        """

        :param loop: asyncio event loop
        :param unix_socket_path: unix socket path to create
        :param socket_mode: If using unix socket, the file mode to set (eg. 0o666)
        :param tcp_socket: (tuple) host, port
        :param reuse_port: If using TCP-socket
        :param shutdown_timeout: (int) seconds to wait for a child-task to shutdown
        """

        self._loop = loop
        if unix_socket_path:
            self._unix = True
            self._path = unix_socket_path
            self._sockmode = socket_mode
        elif tcp_socket:
            self._unix = False
            self._host = tcp_socket[0]
            self._port = tcp_socket[1]
        else:
            raise ValueError("No unix-socket path nor TCP-socket parameters specified! Cannot start server.")
        self._reuse_port = reuse_port
        self._shutdown_timeout = shutdown_timeout

        self._children = set()
        self._server = None

    async def create(self) -> None:
        def _spawn_client_connection_cb(reader: StreamReader, writer: StreamWriter) -> None:
            def done_cb(task, fut) -> None:
                self._children.discard(task)

            task = self._loop.create_task(self._client_request_handler(reader, writer))
            task.add_done_callback(partial(done_cb, task))
            self._children.add(task)
            logger.debug("spawn: len(self._children) = {}".format(len(self._children)))

        if self._unix:
            self._server = await asyncio.start_unix_server(_spawn_client_connection_cb, path=self._path)
            if self._sockmode is not None:
                os.chmod(self._path, self._sockmode)
            logger.info("Started unix-socket server at: {}".format(self._path))
        else:
            if self._reuse_port:  # pragma: no cover
                if sys.platform in ('win32', 'cygwin'):
                    opts = {
                        'host': self._host,
                        'port': self._port,
                        'reuse_address': True,
                    }
                elif os.name == 'posix':
                    if sys.platform.startswith('freebsd'):
                        sockopts = [
                            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
                            (socket.SOL_SOCKET, 0x10000, 1),  # SO_REUSEPORT_LB
                        ]
                        sock = await self.create_custom_socket(self._host, self._port,
                                                               options=sockopts, loop=self._loop)
                        opts = {
                            'sock': sock,
                        }
                    else:
                        opts = {
                            'host': self._host,
                            'port': self._port,
                            'reuse_address': True,
                            'reuse_port': True,
                        }
                else:
                    logger.warning("TCP-socket re-use requested. Didn't detect platform. Not setting for re-use.")

            # Go create a TCP-socket server. Listen for given host/port -pair.
            self._server = await asyncio.start_server(_spawn_client_connection_cb, **opts)
            logger.info("Started TCP-socket server at: {}:{}".format(self._host, self._port))

    @staticmethod
    async def create_custom_socket(host, port, *,  # pylint: disable=too-many-locals
                                   family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM,  # pylint: disable=redefined-builtin
                                   flags=socket.AI_PASSIVE,
                                   options=None,
                                   loop=None):
        if loop is None:
            raise ValueError("Need event loop!")

        res = await loop.getaddrinfo(host, port,
                                     family=family, type=type, flags=flags)
        af, s_typ, proto, _, sa = res[0]  # pylint: disable=invalid-name
        sock = socket.socket(af, s_typ, proto)

        if options is not None:
            for level, optname, val in options:
                sock.setsockopt(level, optname, val)

        sock.bind(sa)

        return sock

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()
        while True:
            logger.debug("Awaiting {} client handlers to finish...".format(len(self._children)))
            remaining = asyncio.gather(*self._children, return_exceptions=True)
            self._children.clear()
            try:
                await asyncio.wait_for(remaining, self._shutdown_timeout)
            except asyncio.TimeoutError:
                logger.warning("Shutdown timeout expired. Remaining handlers terminated.")
                try:
                    await remaining
                except asyncio.CancelledError:
                    pass

            # While this may seem ridiculous, if server wouldn't be closed and a new client-connection would appear,
            # then this would make sense.
            logger.debug("1 second delay before quit")
            await asyncio.sleep(1)
            if not self._children:
                break

        logger.info("Server stop done.")

    def cancellation_event_factory(self) -> asyncio.Event:
        """
        Create an event that gets set when the program is interrupted.
        :return: Event object
        """
        cancellation_event = asyncio.Event()

        def _cancel_handler(num: int) -> None:
            name = signal.Signals(num).name
            pid = os.getpid()
            logger.info('SocketmapResponder [PID: {}] received signal: {} ({}). '
                        'Setting cancellation event.'.format(pid, name, num))
            cancellation_event.set()

        for signal_value in {signal.SIGINT, signal.SIGTERM}:
            # Note: signal_value is doubled. 2nd is the argument.
            # When signal_value is captured, a call into _cancel_handler(signal_value) will be made.
            self._loop.add_signal_handler(signal_value, _cancel_handler, signal_value)

        return cancellation_event

    def responder_task_factory(self, cancellation_event: asyncio.Event) -> asyncio.Task:
        """
        Create a task to run the responder
        :param cancellation_event: Event
        :return: Task object
        """
        if not self._server:
            coro = self.create()
            task = self._loop.create_task(coro)
            self._loop.run_until_complete(task)

        if not self._server:
            raise ValueError("Factory cannot create task. Server not yet created.")
        if not self._loop:
            raise ValueError("Factory cannot create task. Doesn't have the loop.")

        # Task 1: Handle stopping
        async def _stop_running_on_cancel():
            cancellation_task = self._loop.create_task(cancellation_event.wait())
            done, pending = await asyncio.wait([cancellation_task])
            if cancellation_task in done:
                logger.info("Received the cancel event!")
                await self.stop()
            for pending_task in pending:
                logger.debug("Cancelling a pending task:")
                pending_task.cancel()
            asyncio.current_task().cancel()

        cancel_task = self._loop.create_task(_stop_running_on_cancel())

        # Task 2: Handle running
        coro = self._server.serve_forever()
        server_task = self._loop.create_task(coro)

        # Gather task #1 and #2 together.
        # Wait for both of them to complete.
        coro = asyncio.wait(
            [cancel_task, server_task],
            return_when=asyncio.ALL_COMPLETED
        )
        task = self._loop.create_task(coro)

        return task

    async def _client_request_sender(self, queue: Queue, writer: StreamWriter):
        def cleanup_queue():
            while not queue.empty():
                task = queue.get_nowait()
                try:
                    task.cancel()
                except Exception:  # pragma: no cover
                    pass

        try:
            while True:
                fut = await queue.get()
                # Check for shutdown
                if fut is None:
                    return
                logger.debug("_sender() Got new future from queue")
                data = await fut
                logger.debug("_sender() Future await complete: data={}".format(data.hex()))
                writer.write(data)
                logger.debug("_sender() Wrote: {}".format(data.hex()))
                await writer.drain()
        except asyncio.CancelledError:
            cleanup_queue()
        except Exception:  # pragma: no cover
            logger.exception("Exception in sender coro:")
            cleanup_queue()
        finally:
            writer.close()

    async def _client_request_handler(self, reader: StreamReader, writer: StreamWriter) -> None:
        """
        Construct netstring parser
        :param reader:
        :param writer:
        :return:
        """

        stream_reader = StreamReader(maxlen=SocketmapResponder.REQUEST_LIMIT_BYTES)

        # Construct queue for responses ordering
        queue: Queue = asyncio.Queue(maxsize=SocketmapResponder.QUEUE_SIZE_BYTES)

        # Create coroutine which awaits for steady responses and sends them
        sender = asyncio.ensure_future(self._client_request_sender(queue, writer), loop=self._loop)

        class NetstringException(Exception):
            pass

        class WantRead(NetstringException):
            pass

        class ParseError(NetstringException):
            pass

        class EndOfStream(Exception):
            pass

        async def finalize():
            try:
                await queue.put(None)
            except asyncio.CancelledError:  # pragma: no cover
                sender.cancel()
                raise
            await sender

        try:
            while True:
                # Extract and parse request
                string_reader = stream_reader.next_string()
                request_parts = []
                while True:
                    try:
                        buf = string_reader.read()
                    except WantRead:
                        part = await reader.read(SocketmapResponder.CHUNK_SIZE_BYTES)
                        if not part:
                            # pylint: disable=raise-missing-from
                            raise EndOfStream()
                        logger.debug("Read a partial request: {}".format(part.hex()))
                        stream_reader.feed(part)
                    else:
                        if buf:
                            request_parts.append(buf)
                        else:
                            req = b''.join(request_parts)
                            logger.debug("Enq request: {}".format(req.hex()))
                            fut = asyncio.ensure_future(self.process_request(req), loop=self._loop)
                            await queue.put(fut)
                            break
        except ParseError:
            logger.warning("Bad netstring message received")
            await finalize()
        except (EndOfStream, ConnectionError, TimeoutError):
            logger.debug("Client disconnected")
            await finalize()
        except OSError as exc:  # pragma: no cover
            if exc.errno == 107:
                logger.debug("Client disconnected")
                await finalize()
            else:
                logger.exception("Unhandled exception: %s", exc)
                await finalize()
        except asyncio.CancelledError:
            sender.cancel()
            raise
        except Exception:  # pragma: no cover
            logger.exception("Unhandled exception:")
            await finalize()

    @abstractmethod
    async def process_request(self, raw_req: bytes) -> bytes:
        pass
