"""Validate configuration changes in Docker containers.

Docker validation requires that the `docker` executable is on the PATH and
can be executed by the current user.
"""


# Imports.
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from io import IOBase
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import indent
from threading import Thread
from typing import (
    Any, Dict, Generator, Iterable, List, Optional, Protocol, Set, Tuple, Union
)
from queue import Empty, Queue
import json
import pkgutil
import re
import subprocess

import ansible.modules

from lib import logger
from lib.strace.util import hashable_arguments_representation
from lib.util import shell


# For getting into the Docker for Mac vm.
# https://www.bretfisher.com/docker-for-mac-commands-for-getting-into-local-docker-vm/
# https://hub.docker.com/r/justincormack/nsenter1
DOCKER_NSENTER = 'justincormack/nsenter1'
DOCKER_IMAGE = 'dozer/validation'


# Overlay2 Paths.
OVERLAY2 = Path('/var/lib/docker/overlay2')


# Validation paths.
VALIDATION_DIR = Path('/validation')


# Ansible.
ANSIBLE_BUILTIN_MODULE_PATH = Path(ansible.modules.__file__).parent
ANSIBLE_BUILTIN_MODULE_PREFIX = f'{ansible.modules.__package__}.'
ANSIBLE_USR_MODULE_PATH = Path('/usr/share/ansible/plugins/modules')
ANSIBLE_USR_MODULE_PREFIX = 'usr.share.ansible.plugins.modules.'


class Validatable(Protocol):
    """Any object that can be validated."""

    system: str
    executable: str
    arguments: Union[List[str], dict]


class InteractiveSubprocess:
    """A subprocess that supports interactive input and output.

    This class is a context manager, and will not run a subprocess until
    entering the context.

    >>> with InteractiveSubprocess(['some', 'command']) as proc:
    >>>     proc.send_line('some subcommand or input')
    >>>     output_lines = proc.read_stdout_lines(timeout=3)
    """

    def __init__(self, cmd: Any):
        """Create a new interactive subprocess.

        Parameters
        ----------
        cmd : Any
            Any valid command for subprocess.Popen.
        """
        self._cmd = cmd
        self._proc: subprocess.Popen
        self._stdout_queue: Queue
        self._stderr_queue: Queue
        self._stdout_reader: Thread
        self._stderr_reader: Thread

    @staticmethod
    def _read_stream_into_queue(stream: IOBase, queue: Queue):
        """Continue to read from proc output streams and populate queues.

        Parameters
        ----------
        stream : IOBase
            Source stream.
        queue : Queue
            Destination queue.
        """
        while line := stream.readline():
            queue.put(line)

    def __enter__(self):
        """Enter context."""
        self._proc = subprocess.Popen(
            self._cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8'
        )
        self._stdout_queue = Queue()
        self._stderr_queue = Queue()
        self._stdout_reader = Thread(
            target=InteractiveSubprocess._read_stream_into_queue,
            args=(self._proc.stdout, self._stdout_queue),
            daemon=True,
        )
        self._stderr_reader = Thread(
            target=InteractiveSubprocess._read_stream_into_queue,
            args=(self._proc.stderr, self._stderr_queue),
            daemon=True,
        )
        self._stdout_reader.start()
        self._stderr_reader.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        self._proc.stdin.close()
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def send(self, data: str):
        """Send data to stdin.

        Parameters
        ----------
        data : str
            Input string.
        """
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def send_line(self, line: str):
        """Send a line to stdin.

        Parameters
        ----------
        line : str
            Input line. A newline will be added if the line does not end with
            one.
        """
        if line[-1] != '\n':
            line = line + '\n'
        self.send(line)

    def _read_queue_lines(self, queue: Queue, timeout: float) -> List[str]:
        """Read lines from a queue.

        Wait until `timeout` seconds without additional input before returning.

        Parameters
        ----------
        queue : Queue
            Queue to read from.
        timeout : float
            Timeout in seconds. Will block and wait for additional lines until
            none show up in `timeout`.

        Returns
        -------
        List[str]
            All lines received.
        """
        lines = []
        try:
            while True:
                lines.append(queue.get(block=True, timeout=timeout))
        except Empty:
            return lines

    def read_stdout_lines(self, timeout: float = 1) -> List[str]:
        """Read lines from stdout.

        timeout : float
            Timeout in seconds. Will block and wait for additional lines until
            none show up in `timeout`.

        Returns
        -------
        List[str]
            All lines received.
        """
        return self._read_queue_lines(self._stdout_queue, timeout)

    def read_stderr_lines(self, timeout: float = 1) -> List[str]:
        """Read lines from stderr.

        Parameters
        ----------
        timeout : float
            Timeout in seconds. Will block and wait for additional lines until
            none show up in `timeout`.

        Returns
        -------
        List[str]
            All lines received.
        """
        return self._read_queue_lines(self._stderr_queue, timeout)


@dataclass(eq=True, frozen=True, order=True)
class DockerFileChange:
    """A file change as reported by `docker container diff`."""

    change: str
    filename: str

    def __str__(self) -> str:
        """Format self as a string."""
        return f'{self.change} {self.filename}'


@dataclass(eq=True, frozen=True, order=True)
class SharedFileDiff:
    """A diff generated for a file shared by two containers."""

    filename: str
    exe_1_lines: int
    exe_1_diff_lines: int
    exe_2_lines: int
    exe_2_diff_lines: int
    # Exclude diffs from comparison due to noise (timestamp, etc.)
    diff: str = field(compare=False)

    def __str__(self) -> str:
        """Format self as a string."""
        return f'{self.filename}\n{self.diff}'


@dataclass(eq=True, frozen=True, order=True)
class EnvironmentMetadata:
    """Information about the transient state of an environment."""

    cwd: str
    env: Dict[str, str]
    proc: Set[str]


@dataclass(eq=True, frozen=True, order=True)
class ValidatableMetadata:
    """Information about the execution of a validatable object."""

    exit_code: int


# frozen=True makes it safe to use @cached_property.
@dataclass(eq=True, frozen=True)
class ValidationResult:
    """Result from validating two executables."""

    exe_1: Validatable
    exe_2: Validatable
    exe_1_metadata: ValidatableMetadata
    exe_1_env_metadata: EnvironmentMetadata
    exe_2_metadata: ValidatableMetadata
    exe_2_env_metadata: EnvironmentMetadata
    exe_1_files_changed: Tuple[DockerFileChange, ...] = field(default=())
    exe_2_files_changed: Tuple[DockerFileChange, ...] = field(default=())
    shared_file_diffs: Tuple[SharedFileDiff, ...] = field(default=())

    @cached_property
    def valid(self) -> bool:
        """Determine if the result is valid or invalid.

        A result is valid when:

        1. The process metadata is the same.
        2. The set of changed files is equal for both containers.
        3. There are no differences for the files that were added or changed
           (not deleted).

        Returns
        -------
        bool
            True if valid.
        """
        return (
            self.exe_1_env_metadata == self.exe_2_env_metadata
            and set(self.exe_1_files_changed) == set(self.exe_2_files_changed)
            and not self.shared_file_diffs
        )

    @cached_property
    def score(self) -> float:
        """A score in the range 0..1 for how good the validation is.

        Returns
        -------
        float
            Validation score. Will be 1 if the final environments are the same.
        """
        parts = []

        m1 = self.exe_1_env_metadata
        m2 = self.exe_2_env_metadata

        # Current working directory is the same.
        parts.append(int(m1.cwd == m2.cwd))

        # Environment variables are the same.
        shared_env = set(m1.env.keys()) | set(m2.env.keys())
        parts.append(
            sum(1 for k in shared_env if m1.env[k] == m2.env[k])
            / len(shared_env)
        )

        # Current running processes are the same.
        parts.append(len(m1.proc & m2.proc) / len(m1.proc | m2.proc))

        # File differences (unique files, or lines differed in shared files).
        s1_changes = set(self.exe_1_files_changed)
        s2_changes = set(self.exe_2_files_changed)
        if not s1_changes and not s2_changes:
            # There are no changes, so "all changes" are the same.
            parts.append(1)
        else:
            parts.append(
                (
                    len(s1_changes & s2_changes)
                    - len(self.shared_file_diffs)
                    + sum(
                        1 - ((diff.exe_1_diff_lines + diff.exe_2_diff_lines)
                             / (diff.exe_1_lines + diff.exe_2_lines))
                        for diff in self.shared_file_diffs
                    )
                ) / len(s1_changes | s2_changes)
            )

        return sum(parts) / len(parts)

    def __str__(self) -> str:
        """Format self as a string."""
        # Format standard output header.
        output_sections = [
            f'Validation Result:\n'
            f'  - exe_1: {self.exe_1.executable} {self.exe_1.arguments}\n'
            f'  + exe_2: {self.exe_2.executable} {self.exe_2.arguments}\n'
            f'Score:\n  {self.score}'
        ]

        # Get env metadata
        m1 = self.exe_1_env_metadata
        m2 = self.exe_2_env_metadata

        # Format differences in the current working directory.
        if m1.cwd != m2.cwd:
            output_sections.append(
                f'Different Working Directory:\n'
                f'  - {m1.cwd}\n'
                f'  + {m2.cwd}'
            )

        # Format differences in env.
        e1_env = []
        e2_env = []
        for k in sorted(m1.env):
            if k not in m2.env or m1.env[k] != m2.env[k]:
                e1_env.append(f'  - {k}={m1.env[k]}')
        for k in sorted(m2.env):
            if k not in m1.env or m2.env[k] != m1.env[k]:
                e2_env.append(f'  + {k}={m2.env[k]}')
        if e1_env or e2_env:
            output_sections.append('Different Environment Variables:')
        if e1_env:
            output_sections.append('\n'.join(e1_env))
        if e2_env:
            output_sections.append('\n'.join(e2_env))

        # Format differences in the current process list.
        m1_procs = m1.proc - m2.proc
        m2_procs = m2.proc - m1.proc
        if m1_procs or m2_procs:
            output_sections.append(f'Different Running Processes:')
        if m1_procs:
            output_sections.append(
                '\n'.join(f'  - {proc}' for proc in m1_procs)
            )
        if m2_procs:
            output_sections.append(
                '\n'.join(f'  + {proc}' for proc in m2_procs)
            )

        # Format differences in changed files, if any.
        fc1 = set(self.exe_1_files_changed)
        fc2 = set(self.exe_2_files_changed)
        if fc1 != fc2:

            fc1_changes = list(sorted(fc1 - fc2, key=lambda f: f.filename))
            fc2_changes = list(sorted(fc2 - fc1, key=lambda f: f.filename))

            if fc1_changes:
                fc1_diff = '\n'.join(f'  - {change}' for change in fc1_changes)
            else:
                fc1_diff = ''

            if fc2_changes:
                fc2_diff = '\n'.join(f'  + {change}' for change in fc2_changes)
            else:
                fc2_diff = ''

            if fc1_changes or fc2_changes:
                output_sections.append('Different Files Changed:')
            if fc1_changes:
                output_sections.append(fc1_diff)
            if fc2_changes:
                output_sections.append(fc2_diff)

        # Format file diffs.
        if self.shared_file_diffs:
            output_sections.append('Different File Changes:')
            for diff in self.shared_file_diffs:
                output_sections.append(f'  {diff.filename}')
                output_sections.append(indent(diff.diff, '    '))

        # Join all sections.
        output_sections.append('')  # Forces newline at end of join.
        return '\n'.join(output_sections)


@contextmanager
def _image(container: str) -> Generator[str, None, None]:
    """Save a container as an image and yield the sha, then clean up.

    Parameters
    ----------
    container : str
        Container sha.

    Yields
    -------
    str
        Image sha.
    """
    logger.info(f'Committing container `{container}`')
    proc = subprocess.run(
        ['docker', 'container', 'commit', container],
        check=True,
        capture_output=True,
        encoding='utf-8',
    )
    image_sha = proc.stdout.strip()
    try:
        logger.info(f'Yielding image sha `{image_sha}`')
        yield image_sha
    finally:
        subprocess.run(
            ['docker', 'image', 'rm', image_sha],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


@contextmanager
def _run(image: str, cmd: List[str]) -> str:
    """Run a command in a docker container, yield the sha, then clean up.

    Parameters
    ----------
    image : str
        Image identifier.
    cmd : str
        Command to run.

    Yields
    -------
    str
        Container sha.
    """
    logger.info(f'Executing `{cmd}` on `{image}`')
    proc = subprocess.run(
        [
            'docker', 'run', '--hostname=dozer-validation', '-d',
            image, *cmd
        ],
        check=True,
        capture_output=True,
        encoding='utf-8',
    )
    container_sha = proc.stdout.strip()
    subprocess.run(
        ['docker', 'container', 'wait', container_sha],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    logs = subprocess.run(
        ['docker', 'logs', container_sha],
        check=True,
        capture_output=True,
        encoding='utf-8',
    )
    if logs.stdout:
        logger.info(f'Stdout:\n{logs.stdout}')
    if logs.stderr:
        logger.info(f'Stderr:\n{logs.stderr}')
    try:
        logger.info(f'Yielding container sha `{container_sha}`')
        yield container_sha
    finally:
        subprocess.run(
            ['docker', 'rm', container_sha],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


@contextmanager
def _setup_image(setup: Optional[str] = None) -> str:
    """Run setup and yield an image identifier, then clean up.

    Parameters
    ----------
    setup : Optional[str]
        Optional setup script. If none the default image will be yielded
        without executing anything.

    Yields
    -------
    str
        Image identifier.
    """
    if not setup:
        yield DOCKER_IMAGE
    else:
        logger.info(f'Setting up validation image with script:\n{setup}')
        with _run(DOCKER_IMAGE, ['bash', '-c', setup]) as c, _image(c) as i:
            yield i


@contextmanager
def _run_validation(image: str,
                    exe: Validatable) -> Generator[str, None, None]:
    """Run validation and yield the container sha before cleaning up.

    Parameters
    ----------
    image : str
        Image identifier.
    exe : Validatable
        Executable to validate.

    Yields
    -------
    str
        Container sha.
    """
    system = exe.system.casefold()
    if system == 'linux':
        cmd = [
            '/scripts/run_validation.sh',
            shell.join([exe.executable, *exe.arguments])
        ]
    elif system == 'ansible':
        module = shell.quote(_ansible_module_path(exe.executable))
        args = shell.quote(json.dumps({'ANSIBLE_MODULE_ARGS': exe.arguments}))
        cmd = ['/scripts/run_validation.sh', 'python', '-m', module, args]
    else:
        raise ValueError(f'Unknown system `{exe.system}`')

    with _run(image, cmd) as c:
        yield c


@lru_cache
def _ansible_module_path(name: str) -> str:
    """Get an Ansible module import path by module name.

    Parameters
    ----------
    name : str
        Module name.

    Returns
    -------
    str
        Module import path.
    """
    try:
        return next(
            m
            for m in pkgutil.walk_packages(
                [str(ANSIBLE_BUILTIN_MODULE_PATH)],
                str(ANSIBLE_BUILTIN_MODULE_PREFIX)
            )
            if not m.ispkg and m.name.endswith(f'.{name}')
        ).name
    except StopIteration:
        logger.warning(
            f'Cannot find builtin Ansible module by name `{name}`. Validation '
            f'will run assuming that the module is installed to '
            f'{ANSIBLE_USR_MODULE_PATH}. You can download it to the '
            f'validation image during the setup script.'
        )
        return f'{ANSIBLE_USR_MODULE_PREFIX}{name}'


def _build_docker_image():
    """(Re)build the validation dockerfile.

    Raises
    ------
    subprocess.CalledProcessError
        Raised on build failure.
    """
    logger.info('Rebuilding the validation docker image...')
    subprocess.run(
        ['docker', 'build', '-t', DOCKER_IMAGE, '.'],
        cwd=Path(__file__).parent,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    logger.info('Done.')


@lru_cache
def _container_diff(container_sha: str) -> Tuple[DockerFileChange, ...]:
    """Run `docker container diff` on a container.

    Changes to ``VALIDATION_DIR`` are ignored and filtered from output.

    Parameters
    ----------
    container_sha : str
        Container identifier.

    Returns
    -------
    Tuple[DockerFileChange, ...]
        Changed files in the docker diff.
    """
    logger.info(f'Running diff on container `{container_sha}`')
    proc = subprocess.run(
        ['docker', 'container', 'diff', container_sha],
        check=True,
        capture_output=True,
    )
    return tuple(sorted(
        DockerFileChange(
            change=str(change, 'utf-8'),
            filename=str(filename, 'utf-8'),
        )
        for change, filename in map(
            lambda l: l.split(maxsplit=1),
            proc.stdout.splitlines()
        )
        if not filename.startswith(bytes(VALIDATION_DIR))
    ))


def _inspect(reference: str) -> dict:
    """Run inspect on a Docker object.

    Parameters
    ----------
    reference : str
        Object reference.

    Returns
    -------
    dict
        Parsed result from running `docker inspect`.
    """
    proc = subprocess.run(
        ['docker', 'inspect', reference],
        check=True,
        capture_output=True,
        encoding='utf-8',
    )
    return json.loads(proc.stdout)[0]


def _parse_diff(filename: str, lines: List[str]) -> Optional[SharedFileDiff]:
    """Parse a diff generated by executing `_get_diff_cmd`.

    Parameters
    ----------
    filename : str
        Name of the diffed file.
    lines : List[str]
        Output lines from the diff command.

    Returns
    -------
    Optional[SharedFileDiff]
        The parsed diff, if the files differed.
    """
    exe_1_lines = int(lines[0])
    exe_2_lines = int(lines[1])
    diff = ''.join(lines[4:]).strip()  # Lines 2-3 are the full file paths.

    if diff:
        _, _, exe_1_lengths, _, exe_2_lengths = zip(*re.findall(
            r'(@@ -(\d+(?:,(\d+))?) \+(\d+(?:,(\d+))?) @@\n)',
            diff,
        ))
        exe_1_diff_lines = sum(map(
            lambda s: int(s) if s else 1,
            exe_1_lengths,
        ))
        exe_2_diff_lines = sum(map(
            lambda s: int(s) if s else 1,
            exe_2_lengths,
        ))
        return SharedFileDiff(
            filename=filename,
            exe_1_lines=exe_1_lines,
            exe_1_diff_lines=exe_1_diff_lines,
            exe_2_lines=exe_2_lines,
            exe_2_diff_lines=exe_2_diff_lines,
            diff=diff
        )
    else:
        return None


def _get_diff_cmd(i1_upper: Path, i2_upper: Path, filename: str) -> str:
    """Format a diff command for a file from Docker.

    Parameters
    ----------
    i1_upper : Path
        Path to the first image overlay2 UpperDir.
    i2_upper : Path
        Path to the second image overlay2 UpperDir.
    filename : str
        Filename to diff.

    Returns
    -------
    str
        Formatted diff command.
    """
    relative_path = Path(filename).relative_to('/')
    i1_path = str(i1_upper / relative_path)
    i2_path = str(i2_upper / relative_path)
    cmd = (
        f"test -f '{i1_path}' "
        f"&& test -f '{i2_path}' "
        f"&& grep '^' '{i1_path}' | wc -l "
        f"&& grep '^' '{i2_path}' | wc -l "
        f"&& diff --unified=0 '{i1_path}' '{i2_path}'\n"
    )
    return cmd


def _docker_diff_generator(i1_upper: Path,
                           i2_upper: Path,
                           filenames: Iterable[str]
                           ) -> Generator[SharedFileDiff, None, None]:
    """Generate shared file diffs on a Docker vm.

    Parameters
    ----------
    i1_upper : Path
        Path to the first image overlay2 UpperDir.
    i2_upper : Path
        Path to the second image overlay2 UpperDir.
    filenames : Iterable[str]
        Filenames to diff.

    Yields
    -------
    SharedFileDiff
        A diff for all shared files that are not the same.
    """
    logger.info('Running docker diff generator.')
    proc = InteractiveSubprocess([
        'docker', 'run', '--privileged', '--pid=host',
        '--rm', '-i', DOCKER_NSENTER
    ])
    with proc:
        for filename in filenames:
            logger.info(f'Diffing shared file `{filename}`.')
            proc.send_line(_get_diff_cmd(i1_upper, i2_upper, filename))
            lines = proc.read_stdout_lines(timeout=0.5)
            if lines:
                diff = _parse_diff(filename, lines)
                if diff:
                    yield diff


def _local_diff_generator(i1_upper: Path,
                          i2_upper: Path,
                          filenames: Iterable[str]
                          ) -> Generator[SharedFileDiff, None, None]:
    """Generate shared file diffs on the local filesystem.

    Parameters
    ----------
    i1_upper : Path
        Path to the first image overlay2 UpperDir.
    i2_upper : Path
        Path to the second image overlay2 UpperDir.
    filenames : Iterable[str]
        Filenames to diff.

    Yields
    -------
    SharedFileDiff
        A diff for all shared files that are not the same.
    """
    logger.info('Running local diff generator.')
    for filename in filenames:
        logger.info(f'Diffing shared file `{filename}`.')
        proc = subprocess.run(
            f'sudo sh -c "{_get_diff_cmd(i1_upper, i2_upper, filename)}"',
            shell=True,
            capture_output=True,
            encoding='utf-8',
        )
        if proc.stdout:
            diff = _parse_diff(filename, proc.stdout.splitlines(keepends=True))
            if diff:
                yield diff


def _file_diffs(c1_sha: str,
                c2_sha: str,
                filenames: Iterable[str]) -> Tuple[SharedFileDiff, ...]:
    """Run `diff` on all shared files.

    Only diffs that report differences are returned.

    Parameters
    ----------
    c1_sha : str
        Container 1 sha.
    c2_sha : str
        Container 2 sha.
    filenames : Iterable[str]
        Shared filenames.

    Returns
    -------
    Tuple[SharedFileDiff, ...]
        Diffs for all shared files.
    """
    with _image(c1_sha) as i1, _image(c2_sha) as i2:

        # Inspect images and validate driver.
        i1_data = _inspect(i1)
        i1_driver = i1_data['GraphDriver']['Name']
        i2_data = _inspect(i2)
        i2_driver = i2_data['GraphDriver']['Name']
        if i1_driver != 'overlay2' or i2_driver != 'overlay2':
            raise Exception(
                f'Unsupported graph drivers: ({i1_driver}, {i2_driver})'
            )

        # Get upper dir.
        i1_upper = Path(i1_data['GraphDriver']['Data']['UpperDir'])
        i2_upper = Path(i2_data['GraphDriver']['Data']['UpperDir'])

        # Check to see if the overlay2 file path exists. If it does, this
        # likely means Docker is running natively on Linux and we can call
        # diff directly. If it does not, this likely means that Docker is
        # running through a Docker for Mac/Windows vm and we need to attach
        # to the vm to get diffs.
        if OVERLAY2.exists():
            diff_generator = _local_diff_generator
        else:
            diff_generator = _docker_diff_generator

        # Run diffs.
        return tuple(diff_generator(i1_upper, i2_upper, filenames))


def _get_metadata(c: str) -> Tuple[EnvironmentMetadata, ValidatableMetadata]:
    """Get environment metadata from a Docker container.

    Parameters
    ----------
    c : str
        Container sha.

    Returns
    -------
    Tuple[EnvironmentMetadata, ValidatableMetadata]
        Metadata parsed from the container.
    """
    with TemporaryDirectory() as tmp:

        # Copy metadata files to tmp.
        subprocess.run(
            ['docker', 'container', 'cp', f'{c}:{VALIDATION_DIR}/post', tmp],
            check=True
        )

        # Read metadata.
        post_dir = Path(tmp) / 'post'
        with open(post_dir / 'cwd') as fd:
            cwd = fd.read().strip()
        with open(post_dir / 'env') as fd:
            env = dict(map(
                lambda l: l.split('=', maxsplit=1),
                fd.read().splitlines())
            )
        with open(post_dir / 'proc') as fd:
            proc = set(
                p
                for p in fd.read().splitlines()
                if '/scripts/run_validation.sh' not in p
            )

    # Get information about the validatable state.
    c_data = _inspect(c)
    exit_code = c_data['State']['ExitCode']

    # Return metadata.
    env_metadata = EnvironmentMetadata(
        cwd=cwd,
        env=env,
        proc=proc,
    )
    exe_metadata = ValidatableMetadata(
        exit_code=exit_code,
    )
    return env_metadata, exe_metadata


def _validation_result(exe_1: Validatable, c1: str,
                       exe_2: Validatable, c2: str) -> ValidationResult:
    """Inspect two containers and generate a validation result.

    Parameters
    ----------
    exe_1 : Validatable
        Executable run in the first container.
    c1 : str
        First container sha.
    exe_2 : Validatable
        Executable run in the second container.
    c2 : str
        Second container sha.

    Returns
    -------
    ValidationResult
        Validation result from comparing both containers.
    """
    logger.info(
        f'Validating {exe_1.executable} {exe_1.arguments} '
        f'<=> {exe_2.executable} {exe_2.arguments}'
    )

    # Run docker diff on containers.
    exe_1_files_changed = _container_diff(c1)
    exe_2_files_changed = _container_diff(c2)

    # Get shared file diffs.
    shared_files = (
        change.filename
        for change in set(exe_1_files_changed) & set(exe_2_files_changed)
        if change.change.casefold() in ('a', 'c')
    )
    shared_file_diffs = _file_diffs(c1, c2, shared_files)

    # Get post-execution metadata
    exe_1_env_metadata, exe_1_metadata = _get_metadata(c1)
    exe_2_env_metadata, exe_2_metadata = _get_metadata(c2)

    # Return result.
    return ValidationResult(
        exe_1=exe_1,
        exe_2=exe_2,
        exe_1_metadata=exe_1_metadata,
        exe_1_env_metadata=exe_1_env_metadata,
        exe_2_metadata=exe_2_metadata,
        exe_2_env_metadata=exe_2_env_metadata,
        exe_1_files_changed=exe_1_files_changed,
        exe_2_files_changed=exe_2_files_changed,
        shared_file_diffs=shared_file_diffs,
    )


def validate_pair(exe_1: Validatable,
                  exe_2: Validatable,
                  setup: Optional[str] = None,
                  ) -> ValidationResult:
    """Validate two executables produce the same changes.

    Parameters
    ----------
    exe_1 : Validatable
        First executable.
    exe_2 : Validatable
        Second executable.
    setup : Optional[str]
        Bash script to prepare the validation container.

    Returns
    -------
    ValidationResult
        Validation result reporting differences.
    """
    _build_docker_image()

    # Run validation.
    with ExitStack() as stack:
        image = stack.enter_context(_setup_image(setup))
        c1 = stack.enter_context(_run_validation(image, exe_1))
        c2 = stack.enter_context(_run_validation(image, exe_2))
        return _validation_result(exe_1, c1, exe_2, c2)


def validate_pairs(executables: Iterable[Validatable],
                   setup: Optional[str] = None) -> List[ValidationResult]:
    """Validate that all pairs of executables produce the same changes.

    Parameters
    ----------
    executables : Iterable[Validatable]
        Executables for validation.
    setup : Optional[str]
        Bash script to prepare the validation container.

    Returns
    -------
    List[ValidationResult]
        A validation result for every pair of executables from `executables`.
    """
    _build_docker_image()

    with ExitStack() as stack:
        logger.info('Starting validation.')

        # Setup validation image and run validation.
        image = stack.enter_context(_setup_image(setup))
        validation_containers = [
            stack.enter_context(_run_validation(image, exe))
            for exe in executables
        ]

        # Get validation results for all pairs.
        validation_pairs = combinations(
            zip(executables, validation_containers),
            2
        )
        validation_results = []
        for (exe_1, c1), (exe_2, c2) in validation_pairs:
            logger.info(
                f'Validating {exe_1.executable} {exe_1.arguments} '
                f'<=> {exe_2.executable} {exe_2.arguments}'
            )
            validation_results.append(_validation_result(exe_1, c1, exe_2, c2))
        return validation_results


def validation_generator(exe_1: Validatable,
                         setup: Optional[str] = None,
                         ) -> Generator[ValidationResult, Validatable, None]:
    """Generate validations against an executable.

    This generator accepts a source executable, then continually validates
    the executable against new executables sent to it via ``send``. Because
    it is driven by the caller sending new executables, the generator does not
    end by itself, and the caller may want to call ``close`` explicitly.

    Generated validations are cached, and cached results will be returned if
    the same executable is sent to the generator more than once.

    Parameters
    ----------
    exe_1 : Validatable
        Executable for validation.
    setup : Optional[str]
        Bash script to prepare the validation container.

    Yields
    -------
    ValidationResult
        Validation result
    """
    # (Re)build the docker validation image.
    _build_docker_image()

    # Enter validation context.
    validation = None
    with ExitStack() as stack:

        # Build the validation image and run validation for the source
        # executable exe_1.
        image = stack.enter_context(_setup_image(setup))
        c1 = stack.enter_context(_run_validation(image, exe_1))

        # Generate validations forever.
        cache = {}
        while True:

            # Yield validation and receive a new executable to validate.
            exe_2 = yield validation

            # If the validation for the executable is cached, use that.
            key = (
                exe_2.system,
                exe_2.executable,
                hashable_arguments_representation(exe_2.arguments),
            )
            validation = cache.get(key, None)
            if validation is not None:
                logger.info(
                    f'Using cached validation for '
                    f'`{exe_2.executable} {exe_2.arguments}`'
                )
                continue

            # If the validation is not cached, generate and cache it now.
            with _run_validation(image, exe_2) as c2:
                validation = _validation_result(exe_1, c1, exe_2, c2)
                cache[key] = validation
