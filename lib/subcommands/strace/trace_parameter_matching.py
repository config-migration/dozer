"""CLI for generating straces for parameter matching."""


# Imports
from argparse import Namespace

from lib.strace import manager


def run(argv: Namespace):
    """Generate trace files.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    manager.trace_parameter_matching()
