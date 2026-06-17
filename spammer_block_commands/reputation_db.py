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

"""
CLI to view and edit the ASN reputation database used by the Postfix socketmap
responder. Both set-asn and add-net are upserts: re-running them on an existing
key alters that entry.
"""

import configargparse
import logging
import sys

from spammer_block_lib.config import MergingTomlConfigParser
from spammer_block_lib.datasources import Geoip2ASN
from spammer_block_lib.reputation import ReputationDb, Verdict, Source

log = logging.getLogger(__name__)

DEFAULT_LOG_LEVEL = "WARNING"
VERDICT_CHOICES = (Verdict.PASS, Verdict.SPAM)


def _setup_logger(log_level_in: str) -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unknown logging level '{}'!".format(log_level_in))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(console_handler)
    root.setLevel(logging._nameToLevel[log_level_in.upper()])


def _dash(value) -> str:
    """
    Render None/empty as a dash for tabular output.
    """
    return str(value) if value not in (None, "") else "-"


# -- subcommand handlers (return process exit code) ------------------------

def cmd_list(db: ReputationDb, args) -> int:
    """
    Command handler: List records
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    show_asns = args.asns or not args.nets
    show_nets = args.nets or not args.asns

    if show_asns:
        asns = db.iter_asns()
        print("# ASN defaults ({})".format(len(asns)))
        if asns:
            print("{:<10} {:<5} {:<28} {:<26} {}".format(
                "ASN", "VERD", "ORG", "UPDATED", "COMMENT"))
            for r in asns:
                print("{:<10} {:<5} {:<28} {:<26} {}".format(
                    "AS{}".format(r.asn), r.verdict, _dash(r.org)[:28],
                    r.updated_at, _dash(r.comment)))

    if show_nets:
        if show_asns:
            print()
        nets = db.iter_overrides(family=args.family)
        print("# Network overrides ({})".format(len(nets)))
        if nets:
            print("{:<32} {:<5} {:<10} {:<26} {}".format(
                "CIDR", "VERD", "ASN", "UPDATED", "COMMENT"))
            for r in sorted(nets, key=lambda x: (x.family, x.cidr)):
                print("{:<32} {:<5} {:<10} {:<26} {}".format(
                    r.cidr, r.verdict,
                    "AS{}".format(r.asn) if r.asn is not None else "-",
                    r.updated_at, _dash(r.comment)))

    return 0


def cmd_set_asn(db: ReputationDb, args) -> int:
    """
    Command handler: Set ASN
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    db.set_asn(args.asn, args.verdict, org=args.org, comment=args.comment)
    print("Set AS{} -> {}".format(args.asn, args.verdict))

    return 0


def cmd_del_asn(db: ReputationDb, args) -> int:
    """
    Command handler: Delete ASN
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    if db.delete_asn(args.asn):
        print("Deleted AS{}".format(args.asn))

        return 0

    print("No such ASN: AS{}".format(args.asn), file=sys.stderr)

    return 1


def cmd_add_net(db: ReputationDb, args) -> int:
    """
    Command handler: Add network
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    try:
        cidr = db.set_override(args.cidr, args.verdict, asn=args.asn, comment=args.comment)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    print("Set override {} -> {}".format(cidr, args.verdict))

    return 0


def cmd_del_net(db: ReputationDb, args) -> int:
    """
    Command handler: Delete network
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    try:
        if db.delete_override(args.cidr):
            print("Deleted override {}".format(args.cidr))

            return 0
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)

        return 2

    print("No such override: {}".format(args.cidr), file=sys.stderr)

    return 1


def cmd_lookup(db: ReputationDb, args) -> int:
    """
    Command handler: Lookup
    :param db: Database
    :param args: Arguments
    :return: int, exit code
    """
    # Resolve the IP's ASN exactly as the responder does: use --asn if given,
    # otherwise auto-resolve from the GeoLite2-ASN database when one is configured.
    asn = args.asn
    asn_org = None
    if asn is None and args.asn_database:
        try:
            with Geoip2ASN(db_file=args.asn_database) as ds:
                resolved = ds.asn_for_ip(args.ip)
        except (ValueError, OSError) as exc:
            print("error: ASN lookup via {} failed: {}".format(args.asn_database, exc), file=sys.stderr)
            return 2
        if resolved is not None:
            asn, asn_org = resolved

    try:
        resolution = db.resolve(args.ip, asn)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    verdict = resolution.verdict if resolution.verdict is not None else "unknown"
    detail = {
        Source.OVERRIDE: "matched override {}".format(resolution.matched),
        Source.ASN: "matched ASN default {}".format(resolution.matched),
        Source.DEFAULT: "no rule matched; responder policy treats this as '{}'".format(Verdict.PASS),
    }[resolution.source]
    if asn is not None:
        detail += "; AS{}{}".format(asn, " {}".format(asn_org) if asn_org else "")
    print("{}\t{}\t({})".format(args.ip, verdict, detail))

    # Scriptable exit status: 0 pass, 1 spam, 0 unknown (responder treats unknown as pass).
    return 1 if resolution.verdict == Verdict.SPAM else 0


def main() -> None:
    parser = configargparse.ArgumentParser(
        description='View and edit the ASN reputation database',
        default_config_files=['/etc/spammer-block/configuration.toml'],
        config_file_parser_class=MergingTomlConfigParser(
            ['common', 'reputation']
        ),
        ignore_unknown_config_file_keys=True,
    )
    parser.add_argument('--database',
                        env_var='SPAMMER_REPUTATION_DB',
                        help="Path to the LMDB reputation database (env: SPAMMER_REPUTATION_DB).")
    parser.add_argument('--asn-database',
                        env_var='SPAMMER_ASN_DATABASE',
                        help="Path to GeoLite2-ASN.mmdb (env: SPAMMER_ASN_DATABASE). When set, "
                             "'lookup' resolves the IP's ASN automatically (like the responder) "
                             "if --asn is not given.")
    parser.add_argument('--log-level',
                        default=DEFAULT_LOG_LEVEL,
                        help="Logging level. Default: {}".format(DEFAULT_LOG_LEVEL))

    sub = parser.add_subparsers(dest='command', required=True)

    # Sub-parser: list
    p_list = sub.add_parser('list',
                            help="List database contents.")
    p_list.add_argument('--asns', action='store_true',
                        help="Show only ASN defaults.")
    p_list.add_argument('--nets', action='store_true',
                        help="Show only network overrides.")
    p_list.add_argument('--family',
                        type=int, choices=(4, 6),
                        help="Limit overrides to an IP family.")
    p_list.set_defaults(func=cmd_list)

    # Sub-parser: set-asn
    p_set_asn = sub.add_parser('set-asn',
                               help="Add or alter an ASN default verdict.")
    p_set_asn.add_argument('asn', type=int,
                           help="AS number, e.g. 64500.")
    p_set_asn.add_argument('verdict',
                           choices=VERDICT_CHOICES)
    p_set_asn.add_argument('--org',
                           help="AS organisation (for display).")
    p_set_asn.add_argument('--comment',
                           help="Free-text note.")
    p_set_asn.set_defaults(func=cmd_set_asn)

    # Sub-parser: del-asn
    p_del_asn = sub.add_parser('del-asn',
                               help="Delete an ASN default verdict.")
    p_del_asn.add_argument('asn', type=int,
                           help="AS number.")
    p_del_asn.set_defaults(func=cmd_del_asn)

    # Sub-parser: add-net
    p_add_net = sub.add_parser('add-net',
                               help="Add or alter a network/host override.")
    p_add_net.add_argument('cidr',
                           help="CIDR or bare IP, e.g. 203.0.113.0/24 or 203.0.113.55.")
    p_add_net.add_argument('verdict',
                           choices=VERDICT_CHOICES)
    p_add_net.add_argument('--asn', type=int,
                           help="Owning ASN (informational).")
    p_add_net.add_argument('--comment',
                           help="Free-text note.")
    p_add_net.set_defaults(func=cmd_add_net)

    # Sub-parser: del-net
    p_del_net = sub.add_parser('del-net',
                               help="Delete a network/host override.")
    p_del_net.add_argument('cidr',
                           help="CIDR or bare IP to delete.")
    p_del_net.set_defaults(func=cmd_del_net)

    # Sub-parser: lookup
    p_lookup = sub.add_parser('lookup',
                              help="Resolve an IP the way the responder would.")
    p_lookup.add_argument('ip',
                          help="IP-address to resolve.")
    p_lookup.add_argument('--asn', type=int,
                          help="The IP's ASN (enables the ASN-default fallback).")
    p_lookup.set_defaults(func=cmd_lookup)

    # Go parse!
    args = parser.parse_args()
    _setup_logger(args.log_level)

    with ReputationDb(args.database) as db:
        sys.exit(args.func(db, args))


if __name__ == "__main__":
    main()
