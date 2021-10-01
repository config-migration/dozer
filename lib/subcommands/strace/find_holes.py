"""Parser CLI for finding argument holes."""


# Imports
from argparse import Namespace

from lib.strace import manager


def run(argv: Namespace):
    """Find syscall argument holes.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    manager.find_holes()
