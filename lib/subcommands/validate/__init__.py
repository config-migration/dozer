"""Dozer validation API."""


# Imports
from argparse import _SubParsersAction

from lib.subcommands.validate import docker


def init_argparse_action(action: _SubParsersAction):
    """Initialize the validation argument parser.

    Parameters
    ----------
    action : _SubParsersAction
        Validation argument parser.
    """
    docker_parser = action.add_parser(
        'docker',
        help='Run validation through Docker.',
    )
    docker_parser.add_argument(
        '--executable',
        action='append',
        help='Condition for one or more executables from the database to '
             'validate. Must be specified as ``attribute=value``. '
             'Comma separated conditions will be used in conjunction.',
    )
    docker_parser.add_argument(
        '--linux',
        action='append',
        help='A single Linux executable and arguments. Must be in the format '
             '`<executable> [arguments ...]`. Ex. '
             '--linux=\'echo contents > file.txt\'.'
    )
    docker_parser.add_argument(
        '--ansible',
        action='append',
        help='A single Ansible module and JSON serialized arguments. Must be '
             'in the format `<module> [arguments]`. '
             'Ex. --ansible=\'user {"name": "username"}\'.'
    )
    docker_parser.add_argument(
        '--setup',
        action='append',
        help='A bash command that can be used for setup. '
             'Ex. --setup=\'touch file.txt\'.'
    )
    docker_parser.set_defaults(run=docker.run)
