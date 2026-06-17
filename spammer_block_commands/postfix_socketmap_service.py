#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# This file is part of Spammer Block library and tool.
# Spamer Block is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia

import asyncio
import asyncio_glib
import configargparse
import grp
import logging
import os
import pwd
import stat
from gi.repository import GLib
from spammer_block_lib.config import MergingTomlConfigParser
from spammer_block_lib.daemon_log import setup_logger
from systemd_watchdog import watchdog
from typing import Optional

from spammer_block_lib import postfix

log = logging.getLogger(__name__)
wd: watchdog = None

DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_SYSTEMD_WATCHDOG_TIME = 5
DEFAULT_LOG_LEVEL = "WARNING"


def _systemd_watchdog_keepalive() -> bool:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    wd.notify()

    # The function is called repeatedly until it returns G_SOURCE_REMOVE or FALSE,
    # at which point the timeout is automatically destroyed and the function will not be called again.
    return True


def _systemd_mock_watchdog() -> bool:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    log.debug("Systemd watchdog tick/tock")

    # Keep ticking
    return True


def _resolve_uid(owner: Optional[str]) -> int:
    """
    Resolve a user name or numeric uid into a uid.
    :param owner: user name, numeric uid as string, or None.
    :return: numeric uid, or -1 ("leave unchanged") when owner is None.
    """
    if owner is None:
        return -1
    if owner.isdigit():
        return int(owner)
    try:
        return pwd.getpwnam(owner).pw_uid
    except KeyError:
        raise ValueError("Unknown user for socket owner: {!r}".format(owner))


def _resolve_gid(group: Optional[str]) -> int:
    """
    Resolve a group name or numeric gid into a gid.
    :param group: group name, numeric gid as string, or None.
    :return: numeric gid, or -1 ("leave unchanged") when group is None.
    """
    if group is None:
        return -1
    if group.isdigit():
        return int(group)
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise ValueError("Unknown group for socket group: {!r}".format(group))


def _set_socket_ownership(path: str, owner: Optional[str], group: Optional[str]) -> None:
    """
    Adjust ownership/permissions of the just-created unix-socket so Postfix can
    connect to it. The socket file already exists at this point (created when the
    responder bound it).

    Running as root: set both UID and GID via os.chown(). Either may be omitted
    (passed as -1 = leave unchanged).

    Running as non-root: the owner cannot be changed, so only chgrp is possible.
    A non-root process may chgrp a file it owns *only* to a group it is itself a
    member of; chgrp'ing to any other group fails with EPERM. We therefore verify
    membership up front and fail with an actionable error instead of an opaque
    "Operation not permitted" from os.chown().

    Group-write permission is granted *before* the chgrp on purpose: the instant
    group ownership flips to the (Postfix) group, that group already has write
    access, leaving no window in which the new group cannot connect to the socket.

    :param path: unix-socket file path.
    :param owner: desired owner (name or uid); only honoured as root.
    :param group: desired group (name or gid).
    """
    uid = _resolve_uid(owner)
    gid = _resolve_gid(group)
    is_root = os.geteuid() == 0

    try:
        if is_root:
            if uid == -1 and gid == -1:
                log.debug("Running as root but no socket owner/group requested; "
                          "leaving ownership unchanged.")
                return
            os.chown(path, uid, gid)
            log.info("Set unix-socket ownership to uid={} gid={} on {}".format(uid, gid, path))
            return

        # Non-root: the owner cannot be changed, only the group.
        if owner is not None:
            log.warning("Not running as root; cannot set socket owner {!r}. Ignoring it.".format(owner))
        if gid == -1:
            log.debug("Non-root and no socket group requested; leaving socket group unchanged.")
            return

        # A non-root process can chgrp a file it owns only to a group it belongs
        # to. Check membership before modifying anything, so we neither leave the
        # socket mode altered on a doomed attempt nor surface a bare EPERM.
        member_gids = set(os.getgroups()) | {os.getegid(), os.getgid()}
        if gid not in member_gids:
            raise PermissionError(
                "Cannot set unix-socket group to gid={}: the daemon's user (uid={}) is "
                "not a member of that group. Run the daemon as root, or add its user to "
                "the group.".format(gid, os.geteuid()))

        # Grant group-write FIRST, then chgrp (order is deliberate, see docstring).
        current_mode = stat.S_IMODE(os.stat(path).st_mode)
        new_mode = current_mode | stat.S_IWGRP
        if new_mode != current_mode:
            os.chmod(path, new_mode)
            log.info("Granted group-write on unix-socket (mode {:#o} -> {:#o}) on {}".format(
                current_mode, new_mode, path))
        os.chown(path, -1, gid)
        log.info("Changed unix-socket group to gid={} on {}".format(gid, path))
    except OSError as exc:
        # Socket permissions are vital: fail loudly rather than run with a socket
        # Postfix cannot reach.
        log.error("Failed to set unix-socket ownership/permissions on {}: {}".format(path, exc))
        raise


def run_daemon(watchdog_time: int, unix_socket_path: Optional[str], tcp_socket: Optional[tuple[str, int]],
               asn_database_path: Optional[str] = None,
               socket_owner: Optional[str] = None, socket_group: Optional[str] = None,
               reputation_db_path: Optional[str] = None) -> None:
    """
    Main loop
    :param watchdog_time:
    :param unix_socket_path:
    :param tcp_socket:
    :param asn_database_path: Path to GeoLite2-ASN.mmdb (None = auto-detect)
    :param socket_owner: Desired unix-socket owner (name or uid); only as root.
    :param socket_group: Desired unix-socket group (name or gid).
    :param reputation_db_path: Path to the LMDB reputation database (None = none).
    :return:
    """

    policy = asyncio_glib.GLibEventLoopPolicy()
    asyncio_loop = policy.new_event_loop()

    # Systemd watchdog?
    if wd.is_enabled:
        # Sets a function to be called at regular intervals with the default priority, G_PRIORITY_DEFAULT.
        # https://docs.gtk.org/glib/func.timeout_add_seconds.html
        log.debug("Systemd Watchdog enabled")
        GLib.timeout_add_seconds(watchdog_time, _systemd_watchdog_keepalive)
        wd.ready()
    else:
        log.info("Systemd Watchdog not enabled")
        # GLib.timeout_add_seconds(watchdog_time, _systemd_mock_watchdog)

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop. PID: {}".format(os.getpid()))

    responder = postfix.PostfixSocketmapResponder(asyncio_loop, unix_socket_path=unix_socket_path,
                                                  tcp_socket=tcp_socket, asn_database_path=asn_database_path,
                                                  reputation_db_path=reputation_db_path)
    cancel_event = responder.cancellation_event_factory()
    responder_task = responder.responder_task_factory(cancel_event)

    # responder_task_factory() ran create() synchronously, so the unix-socket
    # file now exists on disk. Adjust its ownership/permissions before we start
    # serving so Postfix can connect.
    if unix_socket_path and (socket_owner or socket_group):
        _set_socket_ownership(unix_socket_path, socket_owner, socket_group)

    log.debug("Enter loop")
    asyncio_loop.run_until_complete(responder_task)
    log.debug("Exit loop")
    log.info("Done monitoring for Postfix mapper requests.")


def main() -> None:
    parser = configargparse.ArgumentParser(
        description='Postfix-mapper Spam Blocker',
        default_config_files=['/etc/spammer-block/configuration.toml'],
        config_file_parser_class=MergingTomlConfigParser(
            ['common', 'postfix.socketmap']
        ),
        ignore_unknown_config_file_keys=True,
    )
    parser.add_argument('--unix-socket-path',
                        help="Use unix-socket for Postfix IPC.")
    parser.add_argument('--tcp-socket-host',
                        default=DEFAULT_TCP_HOST,
                        help="Use TCP-socket for Postfix IPC, the host.")
    parser.add_argument('--tcp-socket-port',
                        type=int,
                        help="Use TCP-socket for Postfix IPC.")
    parser.add_argument('--watchdog-time', type=int,
                        default=DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--asn-database',
                        required=True,
                        help="Path to GeoLite2-ASN.mmdb. Default: auto-detect under GeoIP-ASN/.")
    parser.add_argument('--reputation-db',
                        help="Path to the LMDB reputation database (managed by spammer-reputation-db). "
                             "If omitted, all resolvable senders are treated as pass.")
    parser.add_argument('--socket-owner',
                        help="Owner (user name or uid) to set on the unix-socket file. "
                             "Only applied when running as root.")
    parser.add_argument('--socket-group',
                        help="Group (group name or gid) to set on the unix-socket file. "
                             "As root this sets the GID; as non-root it chgrp's the socket "
                             "(group-write is granted first).")
    parser.add_argument('--log-level', default=DEFAULT_LOG_LEVEL,
                        help='Set logging level. Python default is: {}'.format(DEFAULT_LOG_LEVEL))
    parser.add_argument("-c", "--config-file",
                        is_config_file=True,
                        help="Specify config file", metavar="FILE")
    args = parser.parse_args()

    # Determine systemd/watchdog availability BEFORE configuring logging, so the
    # first log line already has the right format: under systemd journald
    # timestamps for us (no in-message timestamp), run manually we add one.
    # watchdog() only reads the environment and sends nothing, so this is safe.
    global wd
    wd = watchdog()
    setup_logger(args.log_level, watchdog=wd.is_enabled)

    # Sanity
    if not args.unix_socket_path and not args.tcp_socket_port:
        raise ValueError("Need either --unix-socket-path or --tcp-socket-host and --tcp-socket-port !")

    # Go run the daemon
    log.info('Starting up ...')
    run_daemon(args.watchdog_time,
               args.unix_socket_path,
               (args.tcp_socket_host, args.tcp_socket_port),
               args.asn_database,
               socket_owner=args.socket_owner,
               socket_group=args.socket_group,
               reputation_db_path=args.reputation_db
               )


if __name__ == "__main__":
    main()
