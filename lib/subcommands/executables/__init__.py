"""Dozer executables CLI."""


# Imports
from argparse import _SubParsersAction

from lib.subcommands.executables import collect_untraced


def init_argparse_action(action: _SubParsersAction):
    """Initialize the executables argument parser.

    Parameters
    ----------
    action : _SubParsersAction
        Executables argument parser.
    """
    # Parse
    untraced_parser = action.add_parser(
        'collect-untraced',
        help='Collect executables from sources that will not be traced.',
    )
    untraced_parser.set_defaults(run=collect_untraced.run)
