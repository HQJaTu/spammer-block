import os
import signal
import asyncio
from asyncinotify import Inotify, Mask
from typing import AsyncIterator, TypeVar, Optional, Tuple
from dbus import (Bus, SessionBus, SystemBus, Interface, proxies)
from pathlib import PosixPath
from .service import SPAM_REPORTER_SERVICE_BUS_NAME
import logging

T = TypeVar('T')
log = logging.getLogger(__name__)


class FolderWatcher:

    def __init__(self, loop: asyncio.AbstractEventLoop, use_system_bus: bool):
        self._loop = loop

        # D-bus stuff:
        self.use_system_bus = use_system_bus
        self._d_bus, \
        self._spammer_reporter_service_proxy, \
        self._spammer_reporter_service_iface = self._prep_dbus(use_system_bus)

    def _prep_dbus(self, use_system_bus: bool) -> Tuple[Bus, proxies.ProxyObject, Interface]:
        if use_system_bus:
            # Global, system wide
            bus = SystemBus()
            log.debug("Using SystemBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))
        else:
            # User's own
            bus = SessionBus()
            log.debug("Using SessionBus for interface {}".format(SPAM_REPORTER_SERVICE_BUS_NAME))

        # Format the service name for bus and interface
        SPAM_REPORTER_SERVICE = SPAM_REPORTER_SERVICE_BUS_NAME.split('.')
        OPATH = "/" + "/".join(SPAM_REPORTER_SERVICE)

        # Get the proxy and interface objects for given D-bus
        proxy = bus.get_object(SPAM_REPORTER_SERVICE_BUS_NAME, OPATH)
        iface = Interface(proxy, dbus_interface=SPAM_REPORTER_SERVICE_BUS_NAME)

        return bus, proxy, iface

    def cancellation_event_factory(self) -> asyncio.Event:
        # Create an event that gets set when the program is interrupted.
        cancellation_event = asyncio.Event()

        def _cancel_handler(num):
            name = signal.Signals(num).name
            log.warning('FolderWatcher received signal: {} ({}). Setting cancellation event.'.format(name, num))
            cancellation_event.set()

        for signal_value in {signal.SIGINT, signal.SIGTERM}:
            # Note: signal_value is doubled. 2nd is the argument.
            # When signal_value is captured, a call into _cancel_handler(signal_value) will be made.
            self._loop.add_signal_handler(signal_value, _cancel_handler, signal_value)

        return cancellation_event

    def watcher_task_factory(self, cancellation_event: asyncio.Event, dirs: list = None) -> asyncio.Task:
        if not dirs:
            raise ValueError("No directories specified to watch")
        task = self._loop.create_task(self._dir_inode_watcher(cancellation_event, dirs))

        return task

    async def _cancellable_async_iterator(self, async_iterator: AsyncIterator[T],
                                          cancellation_event: asyncio.Event) -> AsyncIterator[T]:
        """
        Wrap an async iterator such that it exits when the cancellation event is set.
        """
        cancellation_task = self._loop.create_task(cancellation_event.wait())
        result_iter = async_iterator.__aiter__()
        while not cancellation_event.is_set():
            next_task = self._loop.create_task(result_iter.__anext__())
            done, pending = await asyncio.wait(
                [cancellation_task, next_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            for done_task in done:
                # log.debug("Cancellable async iterator: Iterating done tasks")
                if done_task == cancellation_task:
                    # XXX
                    # log.warning("Yes. This done task is the cancellation task!")
                    # The cancellation token has been set, and we should exit.
                    # Cancel any pending tasks. This is safe as there is no await
                    # between the completion of the wait on the cancellation event
                    # and the pending tasks being cancelled. This means that the
                    # pending tasks cannot have done any work.
                    for pending_task in pending:
                        # log.debug("Cancelling a pending task:")
                        pending_task.cancel()

                    if False:
                        # Now the tasks are cancelled we can await the cancellation
                        # error, knowing they have done no work.
                        for pending_task in pending:
                            try:
                                log.debug("Waiting for a pending task")
                                await pending_task
                            except asyncio.CancelledError:
                                log.debug("psst... it crashed")
                                pass

                    log.debug("Looped all done tasks.")
                else:
                    # We have a result from the async iterator.
                    yield done_task.result()

        # log.debug("Exiting _cancellable_async_iterator()")

    async def _dir_inode_watcher(self, stop_event: asyncio.Event, directories_to_watch: list) -> None:
        """
        Docs:
        - https://asyncinotify.readthedocs.io/en/latest/
        - https://man7.org/linux/man-pages/man7/inotify.7.html
        Example event:
         Inotify event in /tmp/fubar: <Event name=PosixPath('juttu') mask=<Mask.CREATE: 256> cookie=0 watch=<Watch path=PosixPath('/tmp/fubar') mask=<Mask.CREATE|MOVE|MOVED_TO|MOVED_FROM|MODIFY: 450>>>
         Path: PosixPath('/tmp/fubar/juttu')
        Example bash:
        $ inotifywait --format '%w%f' -e create -e delete -e close_write /tmp/fubar/ | xargs /bin/echo
        :return:
        """

        for directory_to_watch in directories_to_watch:
            if not os.path.isdir(directory_to_watch):
                raise ValueError("Given path {} isn't a directory!".format(directory_to_watch))

        with Inotify() as inotify:
            # We're watching only new/ subdir of this Maildir.
            # In Maildir any newly received mail is created into new/. For that create-event can be observed.
            # If user interacts with MUA and moves mail from another folder to here, a moved-to -event
            # is received when mail is move into new/.
            # When MUA sees the new mail, it will be moved into cur/ by MUA.
            # dir_mask = Mask.CREATE | Mask.DELETE | Mask.CLOSE_WRITE | Mask.MOVE
            dir_mask = Mask.CREATE | Mask.MOVED_TO
            for directory_to_watch in directories_to_watch:
                inotify.add_watch(directory_to_watch, dir_mask)
                log.debug("Running Inotify for directory: {}".format(directory_to_watch))

            # Iterate events forever, yielding them one at a time
            async for event in self._cancellable_async_iterator(inotify, stop_event):
                # cancellation_event = make_cancellation_event()
                # async for event in cancellable_aiter(inotify, cancellation_event):
                # Events have a helpful __repr__.  They also have a reference to
                # their Watch instance.
                # XXX
                # log.debug("Inotify event in {}: {}".format(event.path, event))

                # the contained path may or may not be valid UTF-8.  See the note
                # below
                # log.debug("  Path: {}".format(repr(event.path)))
                if Mask.DELETE in event:
                    log.warning("While watching for changes in {}, deleted {}".format(event.watch.path, event.path))
                elif Mask.CREATE in event:
                    log.warning("While watching for changes in {}, created {}".format(event.watch.path, event.path))
                    self.dbus_reporter(event.path)
                elif Mask.CLOSE_WRITE in event:
                    log.warning("While watching for changes in {}, wrote into {}".format(event.watch.path, event.path))
                elif Mask.MOVED_TO in event:
                    log.warning(
                        "While watching for changes in {}, file was moved into {}".format(event.watch.path, event.path))
                    self.dbus_reporter(event.path)
                elif Mask.MOVED_FROM in event:
                    log.warning("While watching for changes in {}, file was moved out from {}".format(event.watch.path,
                                                                                                      event.path))

        # log.debug("Done looping Inotify()")

    def dbus_reporter(self, filename: str) -> None:
        if isinstance(filename, str):
            pass
        elif isinstance(filename, PosixPath):
            filename = str(filename)
        else:
            raise ValueError("Filename isn't in a known type!")

        # As this single-thread process cannot send AND receive, send from an async task.
        # Note: This particular async-task is a Glib one, not asyncio.
        log.debug("Sending ReportFile({}) into D-Bus {}".format(filename, SPAM_REPORTER_SERVICE_BUS_NAME))
        self._spammer_reporter_service_iface.ReportFile(filename,
                                                        reply_handler=self._dbus_reporter_reply_handler,
                                                        error_handler=self._dbus_reporter_error_handler,
                                                        )

    def _dbus_reporter_reply_handler(self, reply: str):
        log.debug("D-bus reporting response: {}".format(reply))

    def _dbus_reporter_error_handler(self, error: str):
        log.debug("D-bus reporting error: {}".format(error))
