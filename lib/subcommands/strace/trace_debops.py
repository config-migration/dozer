"""CLI for tracing modules in a debops playbooks."""


# Imports
from argparse import Namespace

from lib.strace.collection import ansible_playbook


def run(argv: Namespace):
    """Trace modules in debops playbooks.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    ansible_playbook.collect_debops(output_dir=argv.output_dir)
