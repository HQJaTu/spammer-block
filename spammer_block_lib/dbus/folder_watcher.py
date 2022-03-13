import os
from asyncinotify import Inotify, Mask, Event
import logging

log = logging.getLogger(__name__)


class FolderWatcher:

    def __init__(self):
        self._inotify = Inotify()

    def close(self) -> None:
        self._inotify.close()

    async def dir_watcher(self) -> None:
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
        self._inotify.add_watch(dir, Mask.CREATE | Mask.DELETE | Mask.CLOSE_WRITE)

        # Iterate events forever, yielding them one at a time
        async for event in self._inotify:
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
