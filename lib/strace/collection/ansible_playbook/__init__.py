"""Ansible specific strace collection utilities."""


# Imports
from pathlib import Path
from functools import partial
from typing import Dict, Generator, Optional
import json
import os
import subprocess
import sys

from lib import logger
from lib.strace import parser
from lib.strace.classes import Strace
from lib.strace.paths import RAW_STRACES


# Constants
COLLECTOR_NAME = 'strace-collector-ansible-playbook'
DOCKER_IMAGE = f'dozer/{COLLECTOR_NAME}:latest'


# Paths
DOCKER_CONTEXT = Path(__file__).parent
TRACE_DIR = RAW_STRACES / COLLECTOR_NAME
TRACE_DIR.mkdir(exist_ok=True, parents=True)
PLAYBOOK_MOUNT_DESTINATION = Path('/source')


def build_docker_image():
    """(Re)build the collector docker image."""
    logger.info('Building Docker image.')
    subprocess.run(
        ['docker', 'build', '-t', DOCKER_IMAGE, '.'],
        cwd=DOCKER_CONTEXT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect_strace(playbook: Path,
                   output_dir: Path,
                   log_file: Optional[Path] = None,
                   playbook_mount_source: Optional[Path] = None,
                   env: Optional[Dict[str, str]] = None,):
    """Collect straces from Ansible playbook tasks run in a Docker container.

    A single playbook or entire directory containing playbooks, roles, etc.
    may be mounted into the container. The container image also provides
    some playbooks that do not need to be mounted.

    Parameters
    ----------
    playbook : Path
        Path to the playbook to trace. This can be an absolute path to an
        existing or mounted playbook, or a relative path in a directory
        mounted to the default /source mount.
    output_dir : Path
        Path to the local output directory where traces will be stored. This
        may be an absolute path, in which case it will be taken as is. If the
        path is not absolute, it will be treated as relative to the default
        output directory.
    log_file : Path
        Path to a log file for capturing stdout and stderr. Path will be
        relative to the output directory
    playbook_mount_source : Path
        Path on the local system that will be mounted to the Docker container
        for collection. It will be mounted to the destination specified by
        ``playbook_mount_destination`` by default.
    env : Optional[Dict[str, str]]
        Additional environment variables to set.
    """
    # Get final output directory
    # If the original value of output_dir is an absolute path, this just
    # resolves as the original value. Otherwise, it will be relative to
    # TRACE_DIR.
    output_dir = TRACE_DIR / output_dir

    # Build command list

    # Command start
    cmd = [
        'docker', 'run', '--privileged', '--rm',
        '-v', f'{output_dir}:/output',
    ]

    # Add playbook mount if specified
    if playbook_mount_source:

        # Resolve absolute path to the mount source.
        playbook_mount_source = Path.cwd() / playbook_mount_source

        cmd.append(
            f'--mount=source={playbook_mount_source},'
            f'destination={PLAYBOOK_MOUNT_DESTINATION},type=bind,readonly'
        )

    # Add environment variables
    for key, value in (env or {}).items():
        cmd.append('-e')
        cmd.append(f'{key}={value}')

    # Add docker image
    cmd.append(DOCKER_IMAGE)

    # Add flags
    if log_file:
        cmd.append(f'--log-file={log_file}')

    # Add positional arguments
    cmd.append(playbook)

    # Run collection
    logger.info('Collecting strace')
    subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr,)


def collect(*args, **kwargs):
    """The same as collect_strace, but (re)build the Docker image first."""
    # (Re)build docker image first
    build_docker_image()

    # Collect strace
    collect_strace(*args, **kwargs)


def parse(output_dir: Path,
          start_at: str = None) -> Generator[Strace, None, None]:
    """Parse traces from an ansible playbook.

    Parameters
    ----------
    output_dir : Path
        Location of the collection output directory.
    start_at : str
        Dataset to start at.

    Yields
    ------
    Strace
        Parsed strace.
    """
    # Get the final output directory.
    output_dir = TRACE_DIR / output_dir
    output_dir_name = output_dir.stem

    logger.info(f'Parsing straces for {COLLECTOR_NAME} at {output_dir}')

    # Module output directories in output_dir
    module_directories = list(sorted(
        (d for d in output_dir.glob('*') if d.is_dir()),
        key=lambda d: int(d.stem)
    ))

    # Advance until finding the start at position
    if start_at is not None:
        while module_directories and module_directories[0].name != start_at:
            module_directories.pop(0)
        if not module_directories:
            logger.warning('Start-at skipped all traces.')

    # Process each module
    for module_dir in module_directories:

        # Read module metadata
        with open(module_dir / 'metadata.json') as metadata_fd:
            metadata = json.load(metadata_fd)

        logger.info(f'Parsing strace {metadata["index"]}: {metadata["name"]}')

        # Get execution result
        result = metadata['result']

        # Skip failed modules
        if result.get('rc', 0):
            logger.warning('Module execution failed, skipping.')
            continue

        # Warn if not changed. Still parsing these for now.
        stdout = result.get('stdout', None)
        if isinstance(stdout, dict) and not stdout.get('changed', False):
            logger.warning('Module execution did not change system state.')

        # Log arguments.
        arg_str = json.dumps(metadata["args"], indent=4, sort_keys=True)
        logger.info(f'Definition:\n{metadata["module"]} {arg_str}')

        # Get strace file path
        strace_file = module_dir / 'strace.txt'

        # Skip if an strace file is not available.
        # This can happen due to permissions issues in tracing.
        if not os.access(strace_file, os.R_OK):
            logger.warning('Cannot read strace file, skipping')
            continue

        # Parse
        logger.info('Parsing strace file...')
        strace = parser.parse(
            strace_file,
            system='ansible',
            executable=metadata['module'],
            arguments=metadata['args'],
            collector=COLLECTOR_NAME,
            collector_assigned_id=f'{output_dir_name}/{metadata["index"]}',
            strace_file=strace_file,
            metadata=metadata,
        )

        # Normalize
        logger.info('Normalizing strace...')
        strace = strace.normalize()

        # Log parsing completion and yield parsed and normalized trace
        logger.info('Done')
        yield strace


# Specific collectors and parsers
collect_debops = partial(
    collect,
    playbook=Path('/debops-ansible/playbooks/site.yml'),
    output_dir='debops',
    env={'ANSIBLE_ROLES_PATH': '/debops-ansible/roles/'},
    log_file='ansible.log',
)
parse_debops = partial(
    parse,
    output_dir='debops'
)
