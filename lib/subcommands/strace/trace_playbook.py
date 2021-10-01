"""CLI for tracing modules in a playbook."""


# Imports
from argparse import Namespace

from lib.strace.collection import ansible_playbook


def run(argv: Namespace):
    """Trace modules in a playbook.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Parse environment variables
    if argv.env:
        argv.env = dict(e.split('=', 1) for e in argv.env)

    # Collect
    ansible_playbook.collect(
        playbook=argv.playbook,
        output_dir=argv.output_dir,
        playbook_mount_source=argv.playbook_mount_source,
        env=argv.env,
    )
