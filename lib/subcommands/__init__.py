"""Dozer CLI subcommands."""


# Imports
from argparse import _SubParsersAction

from lib.subcommands import (
    comparison, executables, experiment, strace, validate
)


def init_argparse_action(action: _SubParsersAction):
    """Initialize the subcommands argument parser.

    Parameters
    ----------
    action : _SubParsersAction
        Subcommands argument parser.
    """
    # Add experiments
    comparison_parser = action.add_parser(
        'compare',
        description='Manually compare two or more straces.',
        help='Compare straces.'
    )
    comparison.init_argparse_parser(comparison_parser)
    executables_parser = action.add_parser(
        'executables',
        help='Run executable collection for predefined sources.',
    )
    executables.init_argparse_action(executables_parser.add_subparsers(
        dest='executables',
        title='Executables',
        description='Run executable collection for predefined sources.',
        required=True,
    ))
    experiment_parser = action.add_parser(
        'experiment',
        help='Run predefined experiments against existing straces.'
    )
    experiment.init_argparse_action(experiment_parser.add_subparsers(
        dest='experiment',
        title='Experiments',
        description='Run predefined experiments against existing straces.',
        required=True,
    ))
    strace_parser = action.add_parser(
        'strace',
        help='Collect, parse, and process straces.'
    )
    strace.init_argparse_action(strace_parser.add_subparsers(
        dest='strace',
        title='Strace',
        description='Collect, parse, and process straces.',
        required=True,
    ))
    validate_parser = action.add_parser(
        'validate',
        help='Validate system changes made by executables.',
    )
    validate.init_argparse_action(validate_parser.add_subparsers(
        dest='validate',
        title='validate',
        description='Validate system changes made by executables.',
        required=True,
    ))
