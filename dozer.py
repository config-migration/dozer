"""Dozer CLI entrypoint."""


# Imports
import argparse
import logging

from lib import logger, subcommands
from lib.strace.comparison.canonical_form import canonical_repr


def main():
    """Parse argv and run the appropriate action."""
    # Configure argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print additional debug information while running.',
    )
    parser.add_argument(
        '--debug-straces',
        action='store_true',
        help='Print strace information before each comparison. Implies '
             '--debug.'
    )
    parser.add_argument(
        '--syscall-format',
        choices=('standard', 'canonical',),
        help='Strace debug format. Standard prints syscalls using their '
             'default representation. Canonical prints syscalls using their '
             'canonical representation. This option only has an effect with '
             '--debug-straces.'
    )
    subcommands.init_argparse_action(parser.add_subparsers(
        dest='subcommand',
        title='Dozer Subcommands',
        description='These commands expose portions of '
                    'Dozer\'s functionality.',
        help='Run one of these commands to get started.',
        required=True,
    ))

    # Parse args
    args = parser.parse_args()

    # Run (requires subparsers to set a default run function)
    if args.debug or args.debug_straces:
        logger.setLevel(logging.DEBUG)
    if args.debug_straces:
        logger.debug_straces = True
    if args.syscall_format == 'canonical':
        logger.debug_straces_context = canonical_repr
    args.run(args)


if __name__ == '__main__':
    main()
