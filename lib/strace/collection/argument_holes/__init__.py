"""Strace argument hole collector.

This collector runs strace on a set of utilities multiple times with the same
parameters. The result is sets of straces that should be exactly the same
except for hole valued syscall arguments.
"""


# Imports
from itertools import combinations
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Set, Tuple, Union
import subprocess


from lib import logger
from lib.strace import parser, util
from lib.strace.classes import Strace, Syscall, StringLiteral
from lib.strace.paths import RAW_STRACES


# Constants
COLLECTOR_NAME = 'strace-collector-argument-holes'
ANSIBLE_DOCKER_IMAGE = f'dozer/{COLLECTOR_NAME}-ansible:latest'
LINUX_DOCKER_IMAGE = f'dozer/{COLLECTOR_NAME}-linux:latest'
ANSIBLE_MODULES = [
    (
        'command',
        {'ANSIBLE_MODULE_ARGS': {'_raw_params': 'echo "test"'}},
        'ansible-command-echo'
    ),
    (
        'file',
        {'ANSIBLE_MODULE_ARGS': {'path': '/tmp/test', 'state': 'touch'}},
        'ansible-file-touch'
    ),
    (
        'file',
        {'ANSIBLE_MODULE_ARGS': {'path': '/tmp/test', 'state': 'absent'}},
        'ansible-file-rm'
    ),
    (
        'user',
        {'ANSIBLE_MODULE_ARGS': {'name': 'ExampleUser'}},
        'ansible-user-add'
    ),
    (
        'user',
        {'ANSIBLE_MODULE_ARGS': {'name': 'ExampleUser', 'state': 'absent'}},
        'ansible-user-del'
    ),
]
LINUX_EXECUTABLES = [
    ('echo', ['test'], 'linux-echo'),
    ('touch', ['/tmp/test'], 'linux-touch'),
    ('rm', ['-rf', '/tmp/test'], 'linux-rm'),
    ('useradd', ['ExampleUser'], 'linux-useradd'),
    ('userdel', ['ExampleUser'], 'linux-userdel'),
]


# Directories
ANSIBLE_DOCKER_CONTEXT = Path(__file__).parent / 'ansible'
LINUX_DOCKER_CONTEXT = Path(__file__).parent / 'linux'
TRACE_DIR = RAW_STRACES / COLLECTOR_NAME
ANSIBLE_TRACE_DIR = TRACE_DIR / 'ansible'
LINUX_TRACE_DIR = TRACE_DIR / 'linux'
ANSIBLE_TRACE_DIR.mkdir(exist_ok=True, parents=True)
LINUX_TRACE_DIR.mkdir(exist_ok=True, parents=True)


def build_ansible_docker_image():
    """(Re)build the collector Ansible Docker image."""
    logger.info('Building the Ansible Docker image.')
    subprocess.run(
        ['docker', 'build', '-t', ANSIBLE_DOCKER_IMAGE, '.'],
        cwd=ANSIBLE_DOCKER_CONTEXT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect_ansible_strace():
    """Collect straces for Ansbile modules."""
    logger.info('Removing old Ansible traces.')
    for trace in ANSIBLE_TRACE_DIR.glob('**/*.txt'):
        trace.unlink()

    logger.info('Collecting Ansible strace.')
    subprocess.run(
        [
            'docker', 'run', '--privileged', '--rm', '-it',
            '-v', f'{ANSIBLE_TRACE_DIR}:/traces',
            ANSIBLE_DOCKER_IMAGE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def build_linux_docker_image():
    """(Re)build the collector Linux Docker image."""
    logger.info('Building the Linux Docker image.')
    subprocess.run(
        ['docker', 'build', '-t', LINUX_DOCKER_IMAGE, '.'],
        cwd=LINUX_DOCKER_CONTEXT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect_linux_strace():
    """Collect straces for Linux commands."""
    logger.info('Removing old Linux traces.')
    for trace in LINUX_TRACE_DIR.glob('**/*.txt'):
        trace.unlink()

    logger.info('Collecting Linux strace.')
    subprocess.run(
        [
            'docker', 'run', '--privileged', '--rm', '-it',
            '-v', f'{LINUX_TRACE_DIR}:/traces',
            LINUX_DOCKER_IMAGE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def collect():
    """Collect straces for all."""
    build_ansible_docker_image()
    collect_ansible_strace()

    build_linux_docker_image()
    collect_linux_strace()


def parse(*args, **kwargs) -> Generator[Strace, None, None]:
    """Parse all straces for this collector.

    Yields
    ------
    Strace
        Parsed strace.
    """
    logger.info(f'Parsing traces for {COLLECTOR_NAME}.')
    yield from _parse_system('ansible', ANSIBLE_MODULES)
    yield from _parse_system('linux', LINUX_EXECUTABLES)


def _parse_system(system: str,
                  data: List[Tuple[str, Union[List[str], dict], str]]
                  ) -> Generator[Strace, None, None]:
    """Parse all traces for a system.

    Parameters
    ----------
    system : str
        System to parse.
    data : List[Tuple[str, Union[List[str], dict], str]]
        System data.

    Yields
    ------
    List[Strace]
        All parsed straces.
    """
    # Compute the strace dir
    system_trace_dir = TRACE_DIR / system

    # Iterate over each strace executable in the provided data.
    for exe, args, name in data:

        # Compute executable dir
        logger.info(f'Parsing traces for ({system}, {name})')
        exe_trace_dir = system_trace_dir / name

        # Parse each strace file provided for the executable.
        for strace_file in exe_trace_dir.glob('*.txt'):

            logger.info(f'Parsing trace {strace_file.stem}')
            yield (
                parser.parse(
                    strace_file,
                    system=system,
                    executable=exe,
                    arguments=args,
                    collector=COLLECTOR_NAME,
                    collector_assigned_id=f'{name}/{strace_file.stem}',
                    strace_file=strace_file,
                    metadata={}
                )
                .normalize()
            )


def find_holes(strace_sets: Iterable[Iterable[Strace]]) -> Dict[str, Set[int]]:
    """Find syscalls that have hole-type arguments.

    Holes are found by first matching up syscalls from each run of the same
    executable. In theory they should match exactly because it's the same
    executable being run with the same arguments in the same environment.
    However, some traces may experience unexpected interrupts that cause
    the traces to not match, etc. We work around this by just matching syscalls
    until the first place the traces differ. We don't need to do anything fancy
    here, we just need a sufficiently large dataset.

    Parameters
    ----------
    strace_sets : Iterable[Iterable[Strace]
        An iterable containing iterable sets of strace meta objects that should
        be the same except for any hole valued arguments.
    """
    # Syscall holes
    holes = {}

    # Check for each system module
    for executable_straces in strace_sets:

        # Skip if not defined or empty
        if not executable_straces:
            continue

        # Verify straces for only one executable are provided
        executable_strace_keys = set(map(
            lambda s: (
                s.system,
                s.executable,
                util.hashable_arguments_representation(s.arguments)
            ),
            executable_straces
        ))
        if len(executable_strace_keys) > 1:
            raise Exception(
                f'Straces from more than one executable invocation provided'
                f'to find_holes: {executable_strace_keys}'
            )

        # Get the first strace meta just for convenient reference
        logger.info(f'Finding holes in {next(iter(executable_strace_keys))}')

        # Test all pairs of traces
        for trace1, trace2 in combinations(executable_straces, 2):

            for call1, call2 in zip(trace1.trace_lines,
                                    trace2.trace_lines):

                if not isinstance(call1, Syscall):
                    continue

                if not isinstance(call2, Syscall):
                    continue

                if call1.name != call2.name:
                    break

                if call1.name not in holes:
                    holes[call1.name] = set()

                # Update indices
                indices = _find_syscall_holes(call1, call2)
                holes[call1.name] |= indices

    # Return non-empty sets
    return {k: v for k, v in holes.items() if v}


def _find_syscall_holes(s1: Syscall, s2: Syscall) -> Set[int]:
    """Find the indices of holes.

    Given two syscalls which _should_ be exactly the same, return a set
    of indices where their arguments are not equal. This indicates
    arguments that should be considered holes.

    Some syscall arguments functionally determine others. For example,
    the value of write[1] (the string to write) determines the value of
    write[2] (the length to write). We can allow a hole to be punched for
    write[2] (and other such functional dependencies) without any special
    considerations because what matters is the key, not the dependency.
    If the key is not a hole, then all information is preserved. If the
    key is a hole, then it will get punched too.

    Parameters
    ----------
    s1 : Syscall
        First syscall.
    s2 : Syscall
        Second syscall.

    Returns
    -------
    Set[int]
        Indices of different arguments.
    """
    indices = set()
    for idx, (a, b) in enumerate(zip(s1.arguments, s2.arguments)):

        # Not a hole if equal
        if a == b:
            continue

        # Special case for strings
        if (isinstance(a.value, StringLiteral)
                and isinstance(b.value, StringLiteral)):

            # Get string values
            str1 = a.value.value
            str2 = b.value.value

            # If the strings start with /proc or /etc, they are probably
            # used for interacting with procfs or configuration. In
            # particular, `userdel` likes to use procfs to get information
            # about the parent process (which happens to be strace) by PID.
            # Getting this PID to easily filter such statements isn't easy,
            # so just ignore all such accesses. With enough syscall
            # examples, if this argument value should be a hole, it will
            # be added by some call not on the filesystem.
            if any(map(
                    lambda d: str1.startswith(d) and str2.startswith(d),
                    ('/proc', '/etc'))):
                continue

            # If the strings only differ by the PID, then do not consider
            # the argument value as a hole. This is a catchall for other
            # fs operations that use the PID.
            if str2.replace(str(s1.pid), str(s2.pid)) == str2:
                continue

        # Otherwise, add as a hole
        indices.add(idx)

    return indices
