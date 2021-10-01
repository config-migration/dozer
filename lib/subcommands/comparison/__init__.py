"""Dozer comparison CLI."""


# Imports
from argparse import ArgumentParser

from lib.subcommands.comparison import compare


def init_argparse_parser(parser: ArgumentParser):
    """Initialize the comparison argument parser.

    Parameters
    ----------
    parser : ArgumentParser
        Experiments argument parser.
    """
    parser.add_argument(
        's1',
        help='Condition for the first set of straces, which will be compared '
             'to those from s2. Must be specified as ``attribute=value``. '
             'Comma separated conditions will be used in conjunction.'
    )
    parser.add_argument(
        's2',
        help='Condition for the second set of straces, which s1 will be '
             'compared to. Must be specified as ``attribute=value``. '
             'Comma separated conditions will be used in conjunction.'
    )
    parser.add_argument(
        '--load',
        help='Condition for any additional strace definitions to be used '
             'during comparison (may impact preprocessors or scoring methods) '
             'that consider the global strace information. If ``load=False``, '
             'no additional straces will be loaded. If ``load=True``, all '
             'straces will be loaded. Otherwise it must be specified as '
             '``attribute=value``. Comma separated conditions will be used '
             'in conjunction. If not specified, the default is False.'
    )
    parser.add_argument(
        '--by',
        help='Compare by scoring method. Must match one of the predefined '
             'compare* scoring methods from ``lib.strace.comparison``. If not '
             'specified, the default is '
             '``lib.strace.comparison.compare_no_preprocessing``.',
    )
    parser.add_argument(
        '--global-preprocessors',
        help='Comma separated list of single preprocessor names from '
             '``lib.strace.comparison.preprocessing``. If not specified, '
             '``lib.strace.comparison.DEFAULT_SINGLE_PREPROCESSORS`` will be '
             'used.'
    )
    parser.add_argument(
        '--top-n',
        help='Number of top-scoring matches from s1 into s2 to print after '
             'comparison.',
        default=compare.DEFAULT_TOP_N,
        type=int,
    )
    parser.set_defaults(run=compare.run)
