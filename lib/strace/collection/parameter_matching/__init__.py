"""Collector for straces used for parameter matching."""


# Imports
from pathlib import Path
from typing import Generator
import subprocess

from lib import logger
from lib.strace import parser
from lib.strace.classes import Strace
from lib.strace.paths import RAW_STRACES


# Constants
COLLECTOR_NAME = 'strace-collector-parameter-matching'
DOCKER_IMAGE = f'dozer/{COLLECTOR_NAME}:latest'


# Paths
DOCKER_CONTEXT = Path(__file__).parent
TRACE_DIR = RAW_STRACES / COLLECTOR_NAME


# Collected Traces
TRACES = [
    {
        'system': 'linux',
        'executable': 'echo',
        'arguments': ['linux-message-01'],
        'strace_file': 'linux-echo.txt',
    },
    {
        'system': 'linux',
        'executable': 'touch',
        'arguments': ['/tmp/linux-filename-01'],
        'strace_file': 'linux-touch.txt',
    },
    {
        'system': 'linux',
        'executable': 'rm',
        'arguments': ['-rf', '/tmp/linux-filename-02'],
        'strace_file': 'linux-rm.txt',
    },
    {
        'system': 'linux',
        'executable': 'useradd',
        'arguments': ['linux-username-01'],
        'strace_file': 'linux-useradd.txt',
    },
    {
        'system': 'linux',
        'executable': 'userdel',
        'arguments': ['linux-username-02'],
        'strace_file': 'linux-userdel.txt',
    },
    {
        'system': 'ansible',
        'executable': 'command',
        'arguments': {
            'ANSIBLE_MODULE_ARGS': {
                '_raw_params': 'echo ansible-message-01'
            }
        },
        'strace_file': 'ansible-command-echo.txt',
    },
    {
        'system': 'ansible',
        'executable': 'file',
        'arguments': {
            'ANSIBLE_MODULE_ARGS': {
                'path': '/tmp/ansible-filename-01',
                'state': 'touch'
            }
        },
        'strace_file': 'ansible-file-touch.txt',
    },
    {
        'system': 'ansible',
        'executable': 'file',
        'arguments': {
            'ANSIBLE_MODULE_ARGS': {
                'path': '/tmp/ansible-filename-02',
                'state': 'absent'
            }
        },
        'strace_file': 'ansible-file-rm.txt',
    },
    {
        'system': 'ansible',
        'executable': 'user',
        'arguments': {'ANSIBLE_MODULE_ARGS': {'name': 'ansible-username-01'}},
        'strace_file': 'ansible-user-add.txt',
    },
    {
        'system': 'ansible',
        'executable': 'user',
        'arguments': {
            'ANSIBLE_MODULE_ARGS': {
                'name': 'ansible-username-02',
                'state': 'absent'
            }
        },
        'strace_file': 'ansible-user-del.txt',
    },
]


def build_docker_image():
    """Build the collector Docker image."""
    logger.info('Building Docker image.')
    subprocess.run(
        ['docker', 'build', '-t', DOCKER_IMAGE, '.'],
        cwd=DOCKER_CONTEXT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect_strace():
    """Collect straces."""
    logger.info('Removing old strace files.')
    for trace in TRACE_DIR.glob('*.txt'):
        trace.unlink()

    logger.info('Collecting Linux strace.')
    subprocess.run(
        [
            'docker', 'run', '--privileged', '--rm', '-it',
            '-v', f'{TRACE_DIR}:/traces',
            DOCKER_IMAGE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect():
    """(Re)build docker images and collect straces."""
    build_docker_image()
    collect_strace()


def parse(*args, **kwargs) -> Generator[Strace, None, None]:
    """Parse straces.

    Yields
    ------
    Strace
        Parsed strace.
    """
    logger.info(f'Parsing straces for {COLLECTOR_NAME}')

    # Parse traces
    for trace_data in TRACES:

        # Compute values
        strace_file = TRACE_DIR / trace_data['strace_file']
        collector_assigned_id = Path(trace_data['strace_file']).stem

        # Log and parse
        logger.info(f'Parsing {collector_assigned_id}')
        yield (
            parser.parse(
                strace_file,
                system=trace_data['system'],
                executable=trace_data['executable'],
                arguments=trace_data['arguments'],
                collector=COLLECTOR_NAME,
                collector_assigned_id=collector_assigned_id,
                strace_file=strace_file,
            )
            .normalize()
        )
