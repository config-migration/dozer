"""Parser CLI for collecting untraced executables."""


# Imports
from argparse import Namespace

from lib.executables.linux_dockerfiles import (
    DEFAULT_REPOS_FILE,
    parse_executables_from_file
)


def run(argv: Namespace):
    """Collect untraced executables.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    parse_executables_from_file(DEFAULT_REPOS_FILE)
