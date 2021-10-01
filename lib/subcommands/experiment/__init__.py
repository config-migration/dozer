"""Dozer experiments CLI."""


# Imports
from argparse import _SubParsersAction
from pathlib import Path

from lib.strace.collection.parameter_matching import (
    COLLECTOR_NAME as PARAMETER_MATCHING
)
from lib.subcommands.experiment import cross_product, dockerfile_top_100


def init_argparse_action(action: _SubParsersAction):
    """Initialize the experiments argument parser.

    Parameters
    ----------
    action : _SubParsersAction
        Experiments argument parser.
    """
    # Cross-product experiment
    cross_product_parser = action.add_parser(
        'cross-product',
        help='Run the cross-product experiment.'
    )
    cross_product_parser.add_argument(
        '--collector',
        default=PARAMETER_MATCHING,
        help='Name of a collector that provides Ansible and Linux straces.',
    )
    cross_product_parser.set_defaults(run=cross_product.run)

    # Dockerfile Top 100 experiment.
    dockerfile_top_100_parser = action.add_parser(
        'dockerfile-top-100',
        help='Run the Dockerfile Top 100 experiment.'
    )
    dockerfile_top_100_parser.add_argument(
        '--postprocess',
        action='store_true',
        help='Run experiment postprocessing. If this is specified, the '
             'experiment will not be run and experiment options will have no '
             'effect. This takes precedence over `--baseline`.',
    )
    dockerfile_top_100_parser.add_argument(
        '--baseline',
        action='store_true',
        help='Run the baseline experiment. In the baseline, no preprocessing '
             'is performed and straces are compared using the Jaccard '
             'Coefficient scoring method with strict equality.',
    )
    dockerfile_top_100_parser.add_argument(
        '--output-dir',
        type=Path,
        default=dockerfile_top_100.DEFAULT_OUTPUT_DIR,
        help=f'Output directory. '
             f'Default={dockerfile_top_100.DEFAULT_OUTPUT_DIR}',
    )
    dockerfile_top_100_parser.add_argument(
        '--server',
        type=int,
        default=1,
        help='Server number (one-indexed). This option is intended for '
             'distributing analysis among multiple servers. If it is '
             'specified, the experiment will start with the ith dockerfile '
             'trace. This option must be specified with the ``of`` option.',
    )
    dockerfile_top_100_parser.add_argument(
        '--of',
        type=int,
        default=1,
        help='Number of servers (one-indexed). This option is intended for '
             'distributing analysis among multiple servers. If it is '
             'specified, the experiment will process every ith dockerfile '
             'trace. This option must be specified with the ``server`` '
             'option.',
    )
    dockerfile_top_100_parser.add_argument(
        '--report-top-n-matches',
        help=f'Report the top n matching Ansible modules for each dockerfile '
             f'executable in the experiment. This option only affects the '
             f'number of matches printed as output. It does not affect the '
             f'generated output files. '
             f'Default={dockerfile_top_100.DEFAULT_REPORT_TOP_N_MATCHES}.',
        default=dockerfile_top_100.DEFAULT_REPORT_TOP_N_MATCHES
    )
    dockerfile_top_100_parser.set_defaults(run=dockerfile_top_100.run)
