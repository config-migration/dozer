"""Parser CLI for parsing all traces."""


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
    manager.clean(raw=argv.clean, parsed=argv.clean)
    manager.generate_traces()
