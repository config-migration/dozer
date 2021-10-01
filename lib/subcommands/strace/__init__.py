"""Dozer strace CLI."""


# Imports
from argparse import _SubParsersAction
from typing import Any

from lib.strace import COLLECTORS
from lib.subcommands.strace import (
    find_holes,
    parse,
    trace_all,
    trace_argument_holes,
    trace_playbook,
    trace_debops,
    trace_parameter_matching,
    trace_untraced
)


class Choices(set):
    """Argparse choices that supports an empty default.

    Choices behaves like a set, except for acting like Choices.default is a
    member of the set.

    This addresses a known bug in argparse where choices with nargs=*
    fails if no arguments are specified.

    https://bugs.python.org/issue9625
    """

    default = ()

    def __contains__(self, item: Any) -> bool:
        """Determine if item is contained in self.

        Parameters
        ----------
        item : Any
            Any item.

        Returns
        -------
        bool
            True if item is Choices.default or item is contained in self.
        """
        return item is self.default or super().__contains__(item)


def init_argparse_action(action: _SubParsersAction):
    """Initialize the strace argument parser.

    Parameters
    ----------
    action : _SubParsersAction
        Strace argument parser.
    """
    # Find holes
    find_holes_parser = action.add_parser(
        'find-holes',
        help='Find syscall argument holes.'
    )
    find_holes_parser.set_defaults(run=find_holes.run)

    # Parse
    parse_parser = action.add_parser(
        'parse',
        help='Parse all available trace files and perform other knowledge '
             'gathering enterprises.'
    )
    parse_parser.set_defaults(run=parse.run)
    parse_parser.add_argument(
        '--clean',
        action='store_true',
        help='Remove serialized traces and parse everything clean.'
    )
    parse_parser.add_argument(
        '--start-at',
        action='append',
        default=[],
        help='Start parsing at a specific strace. Must be specified as '
             '<collector>=<start-at> and may be specified multiple times.'
    )
    parse_parser.add_argument(
        'collectors',
        help='Collectors to use while parsing. If none are specified all '
             'collectors will be used. Traces must exist for a collector '
             'before parsing.',
        choices=Choices(COLLECTORS.keys()),
        default=Choices.default,
        nargs='*',
    )

    # Trace
    trace_all_parser = action.add_parser(
        'trace-all',
        help='Generate trace files.'
    )
    trace_all_parser.add_argument(
        '--clean',
        action='store_true',
        help='If specified, all cached raw and parsed strace files will be '
             'deleted before generating new strace files.',
    )
    trace_all_parser.set_defaults(run=trace_all.run)

    # Trace argument holes
    trace_argument_holes_parser = action.add_parser(
        'trace-argument-holes',
        help='Generate straces for argument holes.'
    )
    trace_argument_holes_parser.set_defaults(run=trace_argument_holes.run)

    # Trace playbook
    trace_playbook_parser = action.add_parser(
        'trace-playbook',
        help='Trace all modules in an Ansible playbook.',
    )
    trace_playbook_parser.add_argument(
        '--output-dir',
        help='Output directory.',
        default='default',
    )
    trace_playbook_parser.add_argument(
        '--playbook-mount-source',
        help='Path on the local system that will be mounted to the Docker '
             'container for collection. It will be mounted to the destination '
             'specified by ``playbook_mount_destination`` by default.',
    )
    trace_playbook_parser.add_argument(
        '-e', '--env',
        action='append',
        help='Environment variables for the Docker container in key=value '
             'format.'
    )
    trace_playbook_parser.add_argument(
        'playbook',
        help='Playbook to trace.',
    )
    trace_playbook_parser.set_defaults(run=trace_playbook.run)

    # Trace debops
    trace_debops_parser = action.add_parser(
        'trace-debops',
        help='Trace all modules in the debops playbooks.',
    )
    trace_debops_parser.add_argument(
        '--output-dir',
        help='Output directory.',
        default='debops',
    )
    trace_debops_parser.set_defaults(run=trace_debops.run)

    # Trace parameter matching
    trace_parameter_matching_parser = action.add_parser(
        'trace-parameter-matching',
        help='Generate straces for parameter matching.'
    )
    trace_parameter_matching_parser.set_defaults(
        run=trace_parameter_matching.run
    )

    # Trace untraced
    trace_untraced_parser = action.add_parser(
        'trace-untraced',
        help='Trace all untraced executables.'
    )
    trace_untraced_parser.set_defaults(run=trace_untraced.run)
