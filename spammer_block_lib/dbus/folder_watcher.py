import os
import signal
import asyncio
from asyncinotify import Inotify, Mask
from typing import AsyncIterator, TypeVar, Optional
import logging

T = TypeVar('T')
log = logging.getLogger(__name__)


class FolderWatcher:

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

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

    def watcher_task_factory(self, cancellation_event: asyncio.Event) -> asyncio.Task:
        task = self._loop.create_task(self._dir_inode_watcher(cancellation_event))

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
                log.debug("Iterating done tasks")
                from pprint import pprint
                pprint(done_task)
                if done_task == cancellation_task:
                    log.warning("Yes. This done task is the cancellation task!")
                    # The cancellation token has been set, and we should exit.
                    # Cancel any pending tasks. This is safe as there is no await
                    # between the completion of the wait on the cancellation event
                    # and the pending tasks being cancelled. This means that the
                    # pending tasks cannot have done any work.
                    for pending_task in pending:
                        log.debug("Cancelling pending task:")
                        pprint(pending_task)
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

        log.debug("Exiting _cancellable_async_iterator()")

    async def _dir_inode_watcher(self, stop_event: asyncio.Event) -> None:
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

        dir = '/tmp/fubar/'
        if not os.path.isdir(dir):
            raise ValueError("Given path {} isn't a directory!".format(dir))

        log.debug("Running Inotify for directory: {}".format(dir))
        with Inotify() as inotify:
            inotify.add_watch(dir, Mask.CREATE | Mask.DELETE | Mask.CLOSE_WRITE)

            # Iterate events forever, yielding them one at a time
            async for event in self._cancellable_async_iterator(inotify, stop_event):
                # cancellation_event = make_cancellation_event()
                # async for event in cancellable_aiter(inotify, cancellation_event):
                # Events have a helpful __repr__.  They also have a reference to
                # their Watch instance.
                log.debug("Inotify event in {}: {}".format(event.path, event))

                # the contained path may or may not be valid UTF-8.  See the note
                # below
                # log.debug("  Path: {}".format(repr(event.path)))
                if Mask.DELETE in event:
                    log.warning("While watching for changes in {}, deleted {}".format(event.watch.path, event.path))
                elif Mask.CREATE in event:
                    log.warning("While watching for changes in {}, created {}".format(event.watch.path, event.path))
                elif Mask.CLOSE_WRITE in event:
                    log.warning("While watching for changes in {}, wrote into {}".format(event.watch.path, event.path))

        log.debug("Done looping Inotify()")
