"""Collect module straces from running Ansible playbooks."""


# Imports
from contextlib import contextmanager, ExitStack
from functools import wraps
from itertools import chain
from json import JSONDecodeError
from multiprocessing.shared_memory import SharedMemory
from pathlib import Path
from time import time
from typing import Any, Dict, Optional, Set
import argparse
import base64
import copy
import json
import re
import shutil
import sys
import tempfile
import zipfile

from ansible.cli.playbook import PlaybookCLI
from ansible.plugins.action import ActionBase
from ansible.utils import color as ansible_color
import yaml


# Paths
DEFAULT_OUTPUT_DIR = Path('output')
DEFAULT_SOURCE_DIR = Path('.')


# Regex
R_PYTHON = re.compile(r'(?:.*/)?python\d*')
R_MODULE = re.compile(r'(?:.*/)?AnsiballZ_(?P<module>[a-zA-Z0-9_]+)\.py')


# Constants
MAX_ROWS = 50000
ANSIBALLZ_PARAMS = 'ANSIBALLZ_PARAMS = '
ANSIBLE_MODULE_ARGS = 'ANSIBLE_MODULE_ARGS'
INDEX_BYTES = 4
INDEX_NAME = 'dozer_module_index'
ZIPDATA = 'ZIPDATA = '
DEFAULT_EXCLUDED_MODULES = frozenset({
    'command', 'setup', 'service', 'shell', 'systemd', 'sysvinit',
})
ANSIBLE_NOCOLOR = 'ANSIBLE_NOCOLOR'


@contextmanager
def execute_with_strace(output_dir: Path = DEFAULT_OUTPUT_DIR,
                        excluded_modules: Optional[Set[str]]
                        = DEFAULT_EXCLUDED_MODULES):
    """Strace ansible module invocations.

    This context manager patches Ansible's ActionBase and StrategyBase classes
    to execute modules using strace.

    Parameters
    ----------
    output_dir : Path
        Directory for strace output.
    excluded_modules : Optional[Set[str]]
        Modules that will not be traced.
    """
    # Make output directory if it doesn't already exist
    output_dir.mkdir(exist_ok=True, parents=True)

    # If no excluded modules, make it an empty set
    if excluded_modules is None:
        excluded_modules = frozenset()

    # Clean output directory (remove all subdirectories and files)
    for path in output_dir.glob('*'):
        if path.is_dir():
            shutil.rmtree(path)
        if path.is_file():
            path.unlink()

    # Save references to original functions
    action_base_execute = ActionBase._low_level_execute_command

    # Define custom execute that wraps the ActionBase execute function
    @wraps(action_base_execute)
    def _execute_with_strace(self: ActionBase,
                             cmd: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute commands with strace.

        This inner function modifies module commands to be run with strace
        before delegating to the original execute function. Ansible runs tasks
        through worker processes, which means that invocations of this function
        do not share memory/variables with the main process.
        """
        # Just execute the command if gathering facts
        if self._task.action == 'gather_facts':
            return action_base_execute(self, cmd, *args, **kwargs)

        # Get command parts
        parts = cmd.split()

        # Module metadata. This will be None if module is not traced, and
        # defined if the module is traced.
        metadata = None

        # If there are at least two parts, the command may be running a module
        if len(parts) >= 2:

            # Get the potential executable and module path
            executable = parts[0]
            module = parts[1]

            # Check for python and module
            python_match = R_PYTHON.match(executable)
            module_match = R_MODULE.match(module)

            # If it matches a python module that is not being excluded,
            # modify the command to run strace.
            if (python_match
                    and module_match
                    and module_match.group('module') not in excluded_modules):

                # Get index shared memory, parse index, and increment the
                # value stored in shared memory
                index_shm = SharedMemory(name=INDEX_NAME)
                index = int.from_bytes(
                    bytes=index_shm.buf.tobytes(),
                    byteorder=sys.byteorder
                )
                index_shm.buf[:] = (index + 1).to_bytes(
                    byteorder=sys.byteorder,
                    length=INDEX_BYTES
                )
                index_shm.close()

                # Create module output directory
                module_dir = output_dir / str(index)
                module_dir.mkdir(exist_ok=True, parents=True)

                # Read module source
                with open(module, 'r') as fd:
                    source_lines = fd.readlines()

                # Parse zip data
                zip_data = ''
                for line in source_lines:
                    line = line.strip()
                    if line.startswith(ZIPDATA):
                        zip_data = line[len(ZIPDATA) + 3:-3]
                        break

                # Extract zipped data for output
                with ExitStack() as stack:
                    t_fd = stack.enter_context(tempfile.NamedTemporaryFile())
                    t_fd.write(base64.b64decode(zip_data))
                    t_fd.flush()
                    z_fd = stack.enter_context(zipfile.ZipFile(t_fd.name))
                    z_fd.extractall(module_dir)

                # Copy module for output
                shutil.copy(module, module_dir)

                # Parse module arguments
                module_args = {}
                for line in source_lines:
                    line = line.strip()
                    if line.startswith(ANSIBALLZ_PARAMS):
                        start = len(ANSIBALLZ_PARAMS) + 1
                        try:
                            ansiballz_params_str = (
                                line[start:-1]
                                .encode('utf-8')
                                .decode('unicode_escape', errors='ignore')
                            )
                            ansiballz_params = json.loads(ansiballz_params_str)
                            module_args = {
                                key: value
                                for key, value in
                                ansiballz_params[ANSIBLE_MODULE_ARGS].items()
                                if not key.startswith('_ansible')
                            }
                        except (UnicodeError, JSONDecodeError,):
                            print('    Error parsing module params.')

                        break

                # Modify command and print info
                original_command = cmd
                cmd = (
                    f'strace -DDD -f -y -yy -X raw -I 2 -o "| awk '
                    f'\'NR>{MAX_ROWS}{{print "\\""TRUNCATED"\\""; exit}}; '
                    f'{{print}}\' > {module_dir / "strace.txt"}" '
                    f'-e trace=!close {cmd}'
                )
                print(f'    Modified Command: {cmd}')
                print(f'    Args: {module_args}')
                sys.stdout.flush()

                # Compute metadata
                metadata = {
                    'name': self._task.name,
                    'action': self._task.action,
                    'module': module_match.group('module'),
                    'index': index,
                    'original_cmd': original_command,
                    'modified_cmd': cmd,
                    'args': module_args,
                }

        # Don't worry about it. It's probably fine.
        self._task.ignore_errors = True

        # Delegate to the execute method.
        # The loader basedir replacement is to make sure the command is
        # executed in the correct working directory.
        loader_basedir = self._loader.get_basedir()
        self._loader.set_basedir(Path.cwd())
        execute_start_s = time()
        result = action_base_execute(self, cmd, *args, **kwargs)
        execute_end_s = time()
        self._loader.set_basedir(loader_basedir)
        execute_duration_s = execute_end_s - execute_start_s

        # Write metadata if the command was traced.
        # module_dir is defined iff metadata is.
        if metadata is not None:

            # Set execution duration and print info
            metadata['duration'] = execute_duration_s
            print(f'    Execution time: {execute_duration_s:.2f}s')

            # Deep copy result to be safe. This prevents us from accidentally
            # overriding anything when we parse stdout and stderr.
            metadata['result'] = copy.deepcopy(result)

            # Parse stdout as JSON if possible
            try:
                metadata['result']['stdout'] = json.loads(result['stdout'])
            except (TypeError, JSONDecodeError):
                pass

            # Parse stderr as JSON if possible
            try:
                metadata['result']['stderr'] = json.loads(result['stderr'])
            except (TypeError, JSONDecodeError):
                pass

            # Add result to metadata before writing
            with open(module_dir / 'metadata.json', 'w') as fd:
                json.dump(metadata, fd)

        # Return result
        return result

    # Replace original functions with custom ones
    ActionBase._low_level_execute_command = _execute_with_strace

    # 32 bit unsigned shared integer. To be used for module execution index
    # (artificial unique identifier for modules as they are executed). Initial
    # value is zero, and the value is incremented every time strace is run.
    index_shm = SharedMemory(
        name=INDEX_NAME,
        size=INDEX_BYTES,
        create=True,
    )
    index_shm.buf[:] = b'\x00\x00\x00\x00'

    # Yield context and then restore the original behavior.
    try:
        yield
    finally:
        ActionBase._low_level_execute_command = action_base_execute
        index_shm.unlink()


def parse_host_patterns(playbook: Path) -> Set[str]:
    """Parse playbook host patterns.

    Parameters
    ----------
    playbook : Path
        Path to the playbook file.

    Returns
    -------
    Set[str]
        Set of all host patterns from all plays.
    """
    # Read playbook
    with open(playbook, 'r') as fd:
        playbook_data = yaml.full_load(fd)

    # Start set of all parsed host patterns
    host_patterns = set()

    # Get host patterns from each play
    for play in playbook_data:

        # Union any hosts
        if 'hosts' in play:
            host_patterns |= set(
                host for host in play['hosts'] if not host.startswith('!')
            )

        # Get any additional imported playbooks
        if 'import_playbook' in play:
            new_playbook = playbook.parent / play['import_playbook']
            host_patterns |= parse_host_patterns(new_playbook)

    # Return
    return host_patterns


@contextmanager
def _maybe_redirect_std(path: Optional[Path]):
    """Redirect stdout and stderr to the file at ``path``.

    If ``path`` is None, then no redirect will occur.

    Parameters
    ----------
    path : Optional[Path]
        Path to an output file.

    """
    # Noop if no path
    if path is None:
        yield
        return

    # Open output path
    with open(path, 'w') as fd:

        # Save original values
        stdout = sys.stdout
        stderr = sys.stderr
        color = ansible_color.ANSIBLE_COLOR

        # Override
        sys.stdout = fd
        sys.stderr = fd
        ansible_color.ANSIBLE_COLOR = False

        # Yield and restore
        try:
            yield
        finally:
            sys.stdout = stdout
            sys.stderr = stderr
            ansible_color.ANSIBLE_COLOR = color


def trace_playbook(playbook: Path,
                   output_dir: Path = DEFAULT_OUTPUT_DIR,
                   log_file: Optional[Path] = None,
                   source_dir: Path = DEFAULT_SOURCE_DIR,
                   excluded_modules: Optional[Set[str]]
                   = DEFAULT_EXCLUDED_MODULES,
                   no_trace: bool = False,):
    """Trace modules in an Ansible playbook using strace.

    Parameters
    ----------
    playbook : Path
        Path to the playbook to trace. Playbook must be in the YAML format.
    output_dir : Path
        Directory for strace output.
    log_file : Path
        Path to a log file for capturing stdout and stderr. Path will be
        relative to the output directory
    source_dir : Path
        Directory where the playbook to be traced can be found.
    excluded_modules : Optional[Set[str]]
        Modules that will not be traced.
    no_trace : bool
        Run playbook without tracing modules. This is useful for debugging
        purposes, because tracing takes a long time.
    """
    # Normalize playbook path
    playbook = source_dir / playbook

    # Open with context for running playbook.
    with ExitStack() as stack:

        # Strace context. This will ensure all modules are traced when the
        # playbook is run.
        if not no_trace:
            stack.enter_context(execute_with_strace(
                output_dir=output_dir,
                excluded_modules=excluded_modules,
            ))

        # Temporary inventory file context.
        fd = stack.enter_context(tempfile.NamedTemporaryFile())

        # Write inventory.
        # The inventory contains the group [local] with an explicitly defined
        # localhost. It also contains parent groups of [local] named for each
        # host in the playbook hosts. This makes localhost a member of all
        # groups and hopefully means all plays will be run against it.
        inventory_lines = [
            '[local]',
            'localhost ansible_connection=local ansible_host=localhost',
            *chain.from_iterable(
                (f'[{host}]', f'[{host}:children]\nlocal')
                for host in parse_host_patterns(playbook)
            ),
        ]
        fd.write(bytes('\n'.join(inventory_lines), encoding='utf-8'))
        fd.flush()  # Guarantees other processes see writes

        # Get full path to log file if specified
        if log_file is not None:
            log_file = output_dir / log_file

        # Run playbook via CLI
        with _maybe_redirect_std(log_file):
            args = ['ansible-playbook', '-i', fd.name, str(playbook)]
            PlaybookCLI(args=args).run()


def main():
    """Parse args and trace."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Run all plays/roles in an Ansible playbook against '
                    'localhost. Module executions will be traced and recorded '
                    'with strace. To pass additional options through to '
                    'Ansible, set environment variables from '
                    'https://docs.ansible.com/ansible/latest/'
                    'reference_appendices/config.html#environment-variables',
    )
    parser.add_argument(
        '--no-trace',
        action='store_true',
        help='Run playbook without tracing modules. This is useful for '
             'debugging purposes, because tracing takes a long time.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help='Directory for strace output.',
    )
    parser.add_argument(
        '--source-dir',
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help='Source directory where the playbook may be found.'
    )
    parser.add_argument(
        '--log-file',
        type=Path,
        help='Path to a log file for capturing stdout and stderr. Path will '
             'be relative to the output directory.',
    )
    parser.add_argument(
        '--exclude',
        nargs='+',
        action='append',
        help='Modules that will not be traced.',
    )
    parser.add_argument(
        'playbook',
        type=Path,
        help='Playbook to trace',
    )
    argv = parser.parse_args()

    # Normalize module exclude set
    if argv.exclude is not None:
        argv.exclude = set(chain.from_iterable(argv.exclude))
    else:
        argv.exclude = DEFAULT_EXCLUDED_MODULES

    # Trace
    trace_playbook(
        playbook=argv.playbook,
        output_dir=argv.output_dir,
        log_file=argv.log_file,
        source_dir=argv.source_dir,
        no_trace=argv.no_trace,
        excluded_modules=argv.exclude,
    )


if __name__ == '__main__':
    main()
