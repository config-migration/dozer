"""Collector for all untraced executables.

This collector generates straces for previously untraced executables.

Untraced executables are typically generated via the `lib.executables`
module and come from sources outside of Dozer. Executables may also
be supplied manually.

This module is designed to not duplicate traces. If an executable is supplied
to trace, but there is an existing strace for an executable matching that
signature, no action is performed.
"""


# Imports.
from pathlib import Path
from typing import Generator, List, Optional
import json
import shutil
import subprocess

from sqlalchemy import select, tuple_
from sqlalchemy.engine.result import RowProxy

from lib import logger
from lib.strace import parser
from lib.strace.classes import Strace
from lib.strace.paths import RAW_STRACES
from lib.strace.tables import (
    untraced_executables as t_untraced_executables,
    executables as t_executables,
    straces as t_straces
)
from lib.util import shell

# Constants.
COLLECTOR_NAME = 'strace-collector-untraced-executables'
DOCKER_IMAGE = f'dozer/{COLLECTOR_NAME}:latest'


# Paths.
OUTPUT_DIR = RAW_STRACES / COLLECTOR_NAME
DOCKER_CONTEXT = Path(__file__).parent


def _get_untraced_executables(subset: Optional[list] = None
                              ) -> List[RowProxy]:
    """Get untraced executables to trace.

    Not all executables from the `untraced_executables` table will be selected.
    Executables from the table must additionally not match an existing
    executable in the `executables` table that has one or more traces present
    in the `straces` table.

    Parameters
    ----------
    subset : Optional[list]
        List of executable definitions. Each object must have `system`,
        `executable`, `arguments_hash`, and `arguments` attributes. If
        provided, untraced executables must also appear in this list.

    Returns
    -------
    List[RowProxy]
        Iterable containing selected database rows.
    """
    # Execute query
    executables = (
        select((
            t_untraced_executables.c.system,
            t_untraced_executables.c.executable,
            t_untraced_executables.c.arguments_hash,
            t_untraced_executables.c.arguments,
        ))
        .distinct()
        .where(
            tuple_(
                t_untraced_executables.c.system,
                t_untraced_executables.c.executable,
                t_untraced_executables.c.arguments
            )
            .notin_(
                select((
                    t_executables.c.system,
                    t_executables.c.executable,
                    t_executables.c.arguments
                ))
                .where(
                    t_executables.c.id.in_(
                        select((t_straces.c.executable,))
                    )
                )
            )
        )
        .execute()
    )

    # If subset is provided, filter the executables result set to include
    # only those that are in the untraced set. This could be integrated with
    # the above query, but as of 2020-04-09, MySQL produces the warning 1235
    # This version of MySQL doesn't yet support 'comparison of JSON within a
    # ROW in the IN operator'.
    if subset:
        executables_list = list(executables)
        executables = filter(
            lambda exe: (
                (
                    exe.system,
                    exe.executable,
                    exe.arguments_hash,
                    exe.arguments
                ) in executables_list
            ),
            subset
        )

    # Return.
    return list(executables)


def build_docker_image():
    """(Re)build the collector Docker image."""
    logger.info('Building Docker image.')
    subprocess.run(
        ['docker', 'build', '-t', DOCKER_IMAGE, '.'],
        cwd=DOCKER_CONTEXT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect_straces(untraced: Optional[list] = None, ):
    """Collect straces for all untraced executables.

    By default, collect_straces will collect straces for all executables in
    the `untraced_executables` table, provided that there is not a matching
    definition in the `executables` table that has at least one strace.

    Parameters
    ----------
    untraced : Optional[list]
        List of executable definitions. Each object must have `system`,
        `executable`, `arguments_hash`, and `arguments` attributes. They may
        also have a `setup` attribute, containing a shell script to be run in
        the trace container for setup prior to running the trace.

        If provided, it will be used as the source list of untraced
        executables. It will still be filtered to exclude those that already
        have a trace in the dozer database.
    """
    # Get filtered executable definitions.
    # Convert to a list of RowProxy so we can use len.
    logger.info('Getting untraced executables...')
    untraced = _get_untraced_executables(subset=untraced)
    logger.info(f'{len(untraced)} unique untraced executables discovered.')

    # Clean output directory.
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    # If there are no untraced executables, exit after cleaning the output
    # directory. This means that a subsequent call to parse will be a noop.
    if not untraced:
        return

    # Trace each executable.
    logger.info('Tracing executables...')
    for executable in untraced:

        # Unpack
        system = executable.system
        binary = executable.executable
        arguments_hash = executable.arguments_hash.hex()
        arguments = executable.arguments
        setup = getattr(executable, 'setup', '')

        # Get command string.
        cmd_str = shell.join([binary, *arguments])

        # Path for output files.
        strace_dir = (
            OUTPUT_DIR
            / f'{binary.strip("/").replace("/", "_")}_{arguments_hash}'
        )
        strace_dir.mkdir()
        metadata_file = strace_dir / 'metadata.json'

        # Trace.
        logger.info(
            f'Tracing {executable.executable} {executable.arguments} '
            f'({strace_dir.name}).'
        )
        logger.info(f'    Command string: {cmd_str}')
        try:
            subprocess.run(
                [
                    'docker', 'run', '--privileged', '--rm', '-it',
                    '-v', f'{strace_dir}:/traces', DOCKER_IMAGE,
                    cmd_str, 'strace.txt', setup
                ],
                capture_output=True,
                check=True
            )
            returncode = 0
        except subprocess.CalledProcessError as e:
            logger.warning(
                f'Trace failed.\n'
                f'    stdout: {e.stdout}\n'
                f'    stderr: {e.stderr}'
            )
            returncode = e.returncode

        # Write metadata.
        with open(metadata_file, 'w') as fd:
            json.dump(
                {
                    'returncode': returncode,
                    'system': system,
                    'executable': binary,
                    'arguments_hash': arguments_hash,
                    'arguments': arguments,
                },
                fd
            )

    logger.info('Done.')


def collect(subset: Optional[list] = None):
    """(Re)build the docker image and collect traces.

    Parameters
    ----------
    subset : Optional[list]
        List of executable definitions. Each object must have `system`,
        `executable`, and `arguments` attributes. If provided, untraced
        executables must also appear in this list.
    """
    build_docker_image()
    collect_straces(untraced=subset)


def parse(*args, **kwargs) -> Generator[Strace, None, None]:
    """Parse straces.

    Yields
    ------
    Strace
        Parsed strace.
    """
    # Get all trace directories
    strace_dirs = list(OUTPUT_DIR.glob('*/'))

    # Do nothing if none exist.
    if not strace_dirs:
        return

    # Process each output.
    logger.info(f'Parsing traces for {COLLECTOR_NAME}...')
    for strace_dir in OUTPUT_DIR.glob('*/'):

        # Get path to strace file.
        strace_file = strace_dir / 'strace.txt'
        if not strace_file.exists():
            logger.warning(f'No strace file for {strace_dir.name}')
            continue

        # Get path to metadata file.
        metadata_file = strace_dir / 'metadata.json'
        if not metadata_file.exists():
            logger.warning(f'No metadata file for {strace_dir.name}')
            continue

        # Load metadata.
        with open(metadata_file) as fd:
            metadata = json.load(fd)

        # Skip parsing if execution failed.
        if metadata['returncode']:
            logger.warning('Executable execution failed, skipping')
            continue

        # Parse.
        logger.info(f'Parsing {strace_dir.name}')
        yield (
            parser.parse(
                strace_file,
                system=metadata['system'],
                executable=metadata['executable'],
                arguments=metadata['arguments'],
                collector=COLLECTOR_NAME,
                collector_assigned_id=strace_dir.name,
                strace_file=strace_file,
            )
            .normalize()
        )

    logger.info('Done.')
