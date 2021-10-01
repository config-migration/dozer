"""Parser CLI for parsing all traces."""


# Imports
from argparse import Namespace

from lib.strace import manager


def run(argv: Namespace):
    """Parse all known traces.

    The parsed strace objects will be serialized for later use without needing
    to reparse.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Parse start at values
    start_at = {}
    for start in argv.start_at:
        split = start.split('=', 1)
        if not len(split) == 2:
            raise ValueError(f'Invalid start-at value: `{start}`')
        start_at[split[0]] = split[1]

    # Clean if requested
    manager.clean(parsed=argv.clean)

    # Parse
    if not argv.collectors:
        manager.parse(start_at=start_at)
    else:
        manager.parse(set(argv.collectors), start_at=start_at)
