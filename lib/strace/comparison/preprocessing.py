"""Strace preprocessing."""


# Imports
from contextlib import nullcontext
from functools import reduce
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union
import operator
import os
import re

from lib.strace import manager
from lib.strace.classes import (
    Collection,
    DeviceFileDescriptor,
    ExecutableParameter,
    Hole,
    IPFileDescriptor,
    NumberLiteral,
    PathFileDescriptor,
    Strace,
    StringLiteral,
    SyntheticValue,
    SyntheticIntTemplate,
    SyntheticValueTemplate,
    Syscall,
    LiteralValue,
    Literal
)
from lib.strace.comparison import flags
from lib.strace.comparison.syscall_equality import SyscallEquality
from lib.strace.comparison.util import get_full_path


class StracePreprocessor:
    """Strace preprocessor superclass."""

    def __init__(self, syscall_equality: SyscallEquality = nullcontext):
        """Initialize a preprocessor.

        Parameters
        ----------
        syscall_equality : SyscallEquality
            An equality method for comparing syscalls.
        """
        self.syscall_equality = syscall_equality


class SinglePreprocessor(StracePreprocessor):
    """Single strace preprocessor.

    A single preprocessor accepts one strace object for preprocessing.
    Preprocessors of this type are expected to run once during the comparison
    process.
    """

    def __call__(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess an strace.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        with self.syscall_equality():
            self._preprocess(s, all_traces)

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess an strace.

        This is the main method for preprocessing. It must be implemented by
        a subclass and is expected to operate in place.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        raise NotImplementedError()


class PunchHoles(SinglePreprocessor):
    """Remove variable syscall arguments."""

    def _preprocess(self, s: Strace, *args, **kwargs):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Get holes
        holes = manager.holes()

        # Process all lines
        for line in s.trace_lines:

            # Do nothing if line is not a syscall
            if not isinstance(line, Syscall):
                continue

            # Do nothing if syscall type has no holes
            if line.name not in holes:
                continue

            # Punch holes
            for idx in holes[line.name]:
                line.arguments[idx].value = Hole()


class ReplaceFileDescriptors(SinglePreprocessor):
    """Replaces file descriptors with the name of the referenced file.

    If this class has a ``_process_<name>`` method matching a syscall, then
    it will be invoked on the syscall. All other syscalls are skipped.
    """

    def _preprocess(self, s: Strace, *args, **kwargs):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # File descriptor tables for each process/thread. Each table is a
        # Dict[int, str] mapping file descriptors to filename.
        fd_tables = {}

        # Process each syscall.
        for syscall in s.trace_lines:

            # Inherit file descriptors for clone and fork. Tables are distinct
            # unless the flag CLONE_FILES is set, in which case the child
            # shares the table with the parent.
            #
            # On exit, remove the table for that process.
            #
            # Default to an empty file descriptor table if preprocessing gets
            # to a syscall without otherwise creating one. This also happens
            # on initialization for the very first syscall.
            if syscall.name == 'clone':

                current_table = fd_tables[syscall.pid]
                if eval(syscall.arguments[1].value.value) & flags.CLONE_FILES:
                    fd_tables[syscall.exit_code] = current_table
                else:
                    fd_tables[syscall.exit_code] = current_table.copy()

            elif syscall.name in ('__clone2', 'clone3', 'fork', 'vfork'):

                fd_tables[syscall.exit_code] = fd_tables[syscall.pid].copy()

            elif syscall.name in ('_exit', '_Exit', 'exit_group', ):

                del fd_tables[syscall.pid]

            elif syscall.pid not in fd_tables:

                fd_tables[syscall.pid] = {}

            # Get function name
            function_name = f'_process_{syscall.name}'

            # Process
            if hasattr(self, function_name):
                getattr(self, function_name)(syscall, fd_tables[syscall.pid])

    def _replace_first(self, s: Syscall, fd: Dict[int, str]):
        """Replace the first argument of a syscall with a file path.

        Parameters
        ----------
        s: Syscall
            Syscall to modify.
        fd : Dict[int, str]
            Mapping of file descriptors to file names.
        """
        # Get fd
        arg_fd = s.arguments[0].value.value

        # Replace if the fd is a known file
        if arg_fd in fd:
            s.arguments[0].value = StringLiteral(fd[arg_fd])

    _process_connect = _replace_first
    _process_faccessat = _replace_first
    _process_fchdir = _replace_first
    _process_fchmod = _replace_first
    _process_fchmodat = _replace_first
    _process_fchown = _replace_first
    _process_fchown32 = _replace_first
    _process_fchownat = _replace_first
    _process_fsync = _replace_first
    _process_fdatasync = _replace_first
    _process_getdents = _replace_first
    _process_getdents64 = _replace_first
    _process_linkat = _replace_first
    _process_lseek = _replace_first
    _process_read = _replace_first
    _process_readlinkat = _replace_first
    _process_recv = _replace_first
    _process_recvfrom = _replace_first
    _process_recvmsg = _replace_first
    _process_send = _replace_first
    _process_sendto = _replace_first
    _process_sendmsg = _replace_first
    _process_fstat = _replace_first
    _process_fstat64 = _replace_first
    _process_fstatat = _replace_first
    _process_fstatat64 = _replace_first
    _process_newfstatat = _replace_first
    _process_fstatfs = _replace_first
    _process_fstatfs64 = _replace_first
    _process_unlinkat = _replace_first
    _process_utimensat = _replace_first
    _process_futimens = _replace_first
    _process_write = _replace_first

    def _process_close(self, s: Syscall, fd: Dict[int, str]):
        arg_fd = s.arguments[0].value.value
        if arg_fd in fd:
            s.arguments[0].value = StringLiteral(fd[arg_fd])
            del fd[arg_fd]

    def _process_dup(self, s: Syscall, fd: Dict[int, str]):
        # Do nothing on error
        if s.exit_code == -1:
            return s

        # Get old and new fd
        old_fd = s.arguments[0].value.value
        new_fd = s.exit_code

        # Duplicate fd
        if old_fd in fd:
            s.arguments[0].value = StringLiteral(fd[old_fd])
            fd[new_fd] = fd[old_fd]

    _process_dup2 = _process_dup
    _process_dup3 = _process_dup

    def _process_fcntl(self, s: Syscall, fd: Dict[int, str]):
        # Do nothing on error
        if s.exit_code == -1:
            return

        # Get command
        arg_cmd = s.arguments[1].value.value

        # If command => duplicate
        if arg_cmd == flags.F_DUPFD or arg_cmd == flags.F_DUPFD_CLOEXEC:

            # Update fd.
            old_fd = s.arguments[0].value.value
            new_fd = s.exit_code
            if old_fd in fd:
                s.arguments[0].value = StringLiteral(fd[old_fd])
                fd[new_fd] = fd[old_fd]

    _process_fcntl64 = _process_fcntl

    def _process_open(self, s: Syscall, fd: Dict[int, str]):
        # Do nothing if open failed
        if s.exit_code == -1:
            return

        # Record file descriptor
        fd[s.exit_code] = s.arguments[0].value.value

    _process_creat = _process_open

    def _process_openat(self, s: Syscall, fd: Dict[int, str]):
        # Do nothing if open failed
        if s.exit_code == -1:
            return

        # Get parameters
        dir_fd = s.arguments[0].value.value
        path = s.arguments[1].value.value

        # Record file descriptor
        fd[s.exit_code] = get_full_path(dir_fd, path)

        # Replace dir_fd
        if dir_fd in fd:
            s.arguments[0].value = StringLiteral(fd[dir_fd])

    def _process_pipe(self, s: Syscall, fd: Dict[int, str]):
        pipe_fds = s.arguments[0].value.items

        fd[pipe_fds[0].value] = 'pipe_read'
        pipe_fds[0].value = StringLiteral('pipe_read')

        fd[pipe_fds[1].value] = 'pipe_write'
        pipe_fds[1].value = StringLiteral('pipe_write')

    _process_pipe2 = _process_pipe

    def _process_poll(self, s: Syscall, fd: Dict[int, str]):
        for poll in s.arguments[0].value.items:
            if poll.dictionary['fd'] in fd:
                poll.dictionary['fd'] = fd[poll.dictionary['fd']]

    _process_ppoll = _process_poll

    def _process_renameat(self, s: Syscall, fd: Dict[int, str]):
        old_dir_fd = s.arguments[0].value.value
        if old_dir_fd in fd:
            s.arguments[0].value = StringLiteral(fd[old_dir_fd])

        new_dir_fd = s.arguments[2].value.value
        if new_dir_fd in fd:
            s.arguments[2].value = StringLiteral(fd[new_dir_fd])

    _process_renameat2 = _process_renameat

    def _process_select(self, s: Syscall, fd: Dict[int, str]):
        for arg in s.arguments[1:4]:
            fds = arg.value.items
            for idx, item in enumerate(fds):
                arg_fd = item.value
                if arg_fd in fd:
                    fds[idx] = fd[arg_fd]

    _process_pselect = _process_select


class SelectSyscalls(SinglePreprocessor):
    """Select only syscall tracelines.

    This preprocessor returns an strace with only the syscall tracelines. All
    others are removed.
    """

    def _preprocess(self, s: Strace, *args, **kwargs):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        idx = 0
        while idx < len(s.trace_lines):
            if not isinstance(s.trace_lines[idx], Syscall):
                del s.trace_lines[idx]
            else:
                idx += 1


class StripGlobalSyscalls(SinglePreprocessor):
    """Strip all global syscalls.

    A global syscall is one that appears in all known straces.
    """

    def __init__(self, *args, **kwargs):
        """Initialize preprocessor."""
        super().__init__(*args, **kwargs)
        self._all_traces = None
        self._globals = None

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess a pair of straces.

        Parameters
        ----------
        s : Strace
            First strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Compute global syscalls if not already known or changed
        if all_traces is not self._all_traces or self._globals is None:
            self._all_traces = all_traces
            self._globals = reduce(
                operator.and_,
                map(lambda s: set(s.trace_lines), all_traces)
            )

        # Pop globals
        idx = 0
        while idx < len(s.trace_lines):
            if (not hasattr(s.trace_lines[idx], 'executable_parameters')
                    and s.trace_lines[idx] in self._globals):
                s.trace_lines.pop(idx)
            else:
                idx += 1


class StripGlobalSyscallsBySystem(SinglePreprocessor):
    """Strip all global syscalls per system.

    A global system syscall is one that occurs in all straces for that system
    (for example, all Ansible straces).
    """

    def __init__(self, *args, **kwargs):
        """Initialize preprocessor."""
        super().__init__(*args, **kwargs)
        self._all_traces = None
        self._globals = None

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Compute global syscalls per system if not already known or changed
        if all_traces is not self._all_traces or self._globals is None:
            self._all_traces = all_traces
            self._globals = {}
            systems = manager.traces_by(keys=('system',), traces=all_traces)
            for system, straces in systems.items():
                self._globals[system] = reduce(
                    operator.and_,
                    map(lambda s: set(s.trace_lines), straces)
                )

        # Reference system globals
        system_globals = self._globals[s.system]

        # Remove globals
        idx = 0
        while idx < len(s.trace_lines):
            if (not hasattr(s.trace_lines[idx], 'executable_parameters')
                    and s.trace_lines[idx] in system_globals):
                s.trace_lines.pop(idx)
            else:
                idx += 1


def _is_fileglob_match(argument_str: str, parameter_str: str) -> bool:
    """Determine if a syscall argument matches a file glob parameter.

    Shells support a range of globbing operators, but we only support the most
    common `*` and `**` (globstar) wildcards. For additional info on globbing
    operators, see http://man7.org/linux/man-pages/man7/glob.7.html.

    Parameters
    ----------
    argument_str : str
        String representation of a syscall argument.
    parameter_str : str
        String representation of an executable parameter.

    Returns
    -------
    bool
        True iff parameter_str represents a file glob and argument_str
        matches the provided glob expression.
    """
    # If the parameter is unquoted and contains *.
    if (not (parameter_str[0] == parameter_str[-1]
             and (parameter_str[0] == '"' or parameter_str[0] == "'"))
            and '*' in parameter_str):
        parameter_str = parameter_str.replace('**', '[^.].*?')
        parameter_str = parameter_str.replace('*', '[^.][^/]*')
        return bool(re.match(parameter_str, argument_str))
    else:
        return False


def executable_parameter_matches(argument_str: str,
                                 parameter_str: str) -> bool:
    """Determine if a syscall argument matches an executable parameter.

    Parameters
    ----------
    argument_str : str
        String representation of a syscall argument.
    parameter_str : str
        String representation of an executable parameter.

    Returns
    -------
    bool
        True iff the argument and parameter are considered a match.
    """
    # The empty string is always a substring of another string, but this is
    # rarely useful. Return no match for this case.
    if not parameter_str:
        return False

    # Check for file glob.
    if _is_fileglob_match(argument_str, parameter_str):
        return True

    # Check for a substring match (the parameter string is included in the
    # argument string).
    return operator.contains(argument_str, parameter_str)


def executable_parameter_template(argument_type: type,
                                  argument_str: str,
                                  parameter_str: str
                                  ) -> SyntheticValueTemplate:
    """Generate a synthetic value template string.

    Parameters
    ----------
    argument_type : type
        Original type of the syscall argument.
    argument_str : str
        Syscall argument string that is the base of the template.
    parameter_str : str
        Parameter string value that matches primitive.

    Returns
    -------
    str
        Formatted template string.
    """
    if argument_type is int:
        return SyntheticIntTemplate()
    elif argument_type is str:
        if _is_fileglob_match(argument_str, parameter_str):
            return '{0}'
        else:
            return (
                argument_str
                .replace('{', '{{')
                .replace('}', '}}')
                .replace(parameter_str, '{0}')
            )
    else:
        raise Exception(f'Unsupported primitive type: {argument_type}')


class GenerateSyntheticValues(SinglePreprocessor):
    """Replace syscall argument values with synthetic values.

    This preprocessor returns an strace where syscall argument values matching
    one of the executable parameters have been replaced with a synthetic value.
    It will also set the attribute ``s.executable_parameters`` to a list of all
    executable parameters that occur within the strace. All syscalls containing
    executable_parameters will get a similar ``executable_parameters``
    attribute if they contain any.

    Executable parameter matching and templating may be overridden by supplying
    custom functions to the ``matches`` and ``template`` arguments of
    ``__init__``.
    """

    def __init__(self,
                 *args,
                 matches: Callable[[str, str], bool]
                 = executable_parameter_matches,
                 template: Callable[[type, str, str], SyntheticValueTemplate]
                 = executable_parameter_template,
                 **kwargs):
        """Initialize preprocessor.

        Parameters
        ----------
        matches : Callable[[str, str], bool]
            Callable that accepts the string arguments (syscall argument,
            executable argument) and returns a bool indicating whether they
            match. Defaults to ``preprocessing.executable_parameter_matches``.
        template : Callable[[type, str, str], SyntheticValueTemplate]
            Callable that produces a synthetic value template for replaced
            parameters. The callable will receive the original primitive type,
            the primitive string representation, and the executable parameter
            string representation. Defaults to
            ``preprocessing.executable_parameter_template``.
        """
        super().__init__(*args, **kwargs)
        self.matches = matches
        self.template = template

    def _preprocess(self, s: Strace, *args, **kwargs):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Get executable parameters
        executable_parameters = ExecutableParameter.get_parameters(s)

        # Keep a dictionary of executable parameters that have been used in
        # one of the strace syscalls.
        used_parameters = {}

        # Replace values in syscall arguments
        for syscall in s.trace_lines:

            # All executable parameters used in the current syscall
            syscall_used_parameters = {}

            # Replace all values in the syscall arguments
            for arg in syscall.arguments:
                syscall_used_parameters.update(
                    self._replace_values_literal(
                        arg, executable_parameters
                    )
                )

            # If any parameters were used by the syscall, add them to the
            # syscall and update the full set of used parameters.
            if syscall_used_parameters:
                syscall.executable_parameters = list(
                    syscall_used_parameters.values()
                )
                used_parameters.update(syscall_used_parameters)

        # Set strace executable parameters to all that were used
        s.executable_parameters = list(used_parameters.values())

    def _replace_values_literal(self,
                                literal: Literal,
                                executable_parameters:
                                List[ExecutableParameter]
                                ) -> Dict[str, ExecutableParameter]:
        """Replace values in a literal.

        Parameters
        ----------
        literal : Literal
            Literal to perform replacement in.
        executable_parameters : List[ExecutableParameter]
            Executable parameters to match against.

        Returns
        -------
        Dict[str, ExecutableParameter]
            All executable parameters used during replacement, keyed by the
            executable parameter key.
        """
        # Skip any arguments that don't have a value
        if not isinstance(literal, Literal):
            return {}

        # What we actually care about is the argument value, not the
        # named wrapper.
        arg_value = literal.value

        # If the value is a collection, then replace values in that collection
        # and return the dictionary of executable parameters that were used.
        if isinstance(arg_value, Collection):
            return self._replace_values_collection(
                arg_value, executable_parameters
            )

        # If the value is not a collection, it must be a primitive class.
        # Try to find a match for it.
        executable_parameter, template = self._find_match(
            arg_value, executable_parameters
        )

        # If a match was found, do the replacement
        if executable_parameter:
            literal.value = SyntheticValue(
                executable_parameter=executable_parameter,
                original_value=literal.value,
                template=template
            )
            return {executable_parameter.key: executable_parameter}
        else:
            return {}

    def _replace_values_collection(self,
                                   value: Collection,
                                   executable_parameters:
                                   List[ExecutableParameter]
                                   ) -> Dict[str, ExecutableParameter]:
        """Replace all values in a collection.

        Parameters
        ----------
        value : Collection
            Collection to perform replacement in.
        executable_parameters : List[ExecutableParameter]
            Executable parameters to match against.

        Returns
        -------
        Dict[str, ExecutableParameter]
            All executable parameters used during replacement, keyed by the
            executable parameter key.
        """
        used_parameters = {}
        for idx, item in enumerate(value.items):
            used_parameters.update(self._replace_values_literal(
                item,
                executable_parameters
            ))
        return used_parameters

    def _find_match(self,
                    value: LiteralValue,
                    executable_parameters: List[ExecutableParameter]
                    ) -> Tuple[
                        Optional[ExecutableParameter],
                        Optional[SyntheticValueTemplate]
                    ]:
        """Find an executable parameter matching a value.

        Currently, the only supported primitive values are NumberLiteral and
        StringLiteral. Container values are not supported in matching.

        Parameters
        ----------
        value : LiteralValue
            A syscall value.
        executable_parameters : List[ExecutableParameter]
            Executable parameters to match against.

        Returns
        -------
        Optional[ExecutableParameter]
            The first matching executable parameter.
        Optional[str]
            Template string for a synthetic value.
        """
        # For numbers, parse the primitive value as an int.
        if isinstance(value, NumberLiteral):
            primitive_type = int
            primitive_value = str(value.value)

        # For strings, process escape characters and replace
        elif isinstance(value, StringLiteral):
            primitive_type = str
            primitive_value = (
                value.value
                .encode('utf-8')
                .decode('unicode_escape', errors='ignore')
                .strip()
            )

        # For path and device file descriptors, use the file path
        elif isinstance(value, (PathFileDescriptor, DeviceFileDescriptor)):
            primitive_type = str
            primitive_value = value.path

        # For ip file descriptors, use the destination address
        elif isinstance(value, IPFileDescriptor):
            primitive_type = str
            primitive_value = value.destination

        # Skip all other arguments types.
        else:
            return None, None

        # Compare against all executable parameters
        for parameter in executable_parameters:

            # Get parameter as a string value
            parameter_str = str(parameter.parameter_value)

            # If the parameter string is non-empty and matches the primitive
            # value, replace it.
            if (parameter_str
                    and self.matches(primitive_value, parameter_str)):
                template = self.template(
                    primitive_type, primitive_value, parameter_str
                )
                return parameter, template

        # Default for no match
        return None, None


class AnsibleStripLastWrite(SinglePreprocessor):
    """Strip the last call to write for ansible straces.

    All ansible modules write a JSON payload to stdout as one of the last steps
    before exiting. This preprocessor removes that write call, which might
    otherwise affect things like synthetic arguments.
    """

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Do nothing if the system is not Ansible
        if s.system != 'ansible':
            return

        # Find and remove only the last write call, if any
        for idx in range(len(s.trace_lines) - 1, -1, -1):
            if s.trace_lines[idx].name == 'write':
                del s.trace_lines[idx]
                break


class ReplacePIDInLockFiles(SinglePreprocessor):
    """Replace process PID in lock file /etc paths.

    *.lock files are created by first creating a *.pid file and linking. This
    causes similar calls to not match, as the process PID changes per run.
    This preprocessor transforms calls like the following

    651   openat(-100, "/etc/passwd.651", 0x241, 0600) = 5
    651   write(5, "651\0", 4) = 4
    651   link("/etc/passwd.651", "/etc/passwd.lock") = 0
    651   stat("/etc/passwd.651", {st_mode=0100600, st_size=4, ...}) = 0
    651   unlink("/etc/passwd.651") = 0

    to

    651   openat(-100, "/etc/passwd.PID", 0x241, 0600) = 5
    651   write(5, "PID\0", 4) = 4
    651   link("/etc/passwd.PID", "/etc/passwd.lock") = 0
    651   stat("/etc/passwd.PID", {st_mode=0100600, st_size=4, ...}) = 0
    651   unlink("/etc/passwd.PID") = 0
    """

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        for syscall in s.trace_lines:

            # Get function name
            function_name = f'_process_{syscall.name}'

            # Process
            if hasattr(self, function_name):
                getattr(self, function_name)(syscall)

    def _default_process_path(self, s: Syscall):
        path = s.arguments[0].value.value
        if path.startswith('/etc/') and path.endswith(f'.{s.pid}'):
            s.arguments[0].value.value = path[:-len(str(s.pid))] + 'PID'

    _process_link = _default_process_path
    _process_stat = _default_process_path
    _process_unlink = _default_process_path

    def _default_process_at(self, s: Syscall):
        path = get_full_path(
            s.arguments[0].value.value,
            s.arguments[1].value.value
        )
        if isinstance(path, tuple):
            _, path = path
        if path.startswith('/etc/') and path.endswith(f'.{s.pid}'):
            s.arguments[1].value.value = path[:-len(str(s.pid))] + 'PID'

    _process_openat = _default_process_at

    def _process_write(self, s: Syscall):
        if s.arguments[1].value.value == f'{s.pid}\\0':
            s.arguments[1].value.value = 'PID\\0'


class ReplacePIDInProcfs(SinglePreprocessor):
    """Replace process PID in procfs access.

    Access to /proc/{s.pid} is equivalent to /proc/self. This preprocessor
    transforms calls so that they can match across different runs with
    different PIDs.
    """

    def _preprocess(self, s: Strace, all_traces: Iterable[Strace]):
        """Preprocess.

        Parameters
        ----------
        s : Strace
            Strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        for syscall in s.trace_lines:

            # Get function name
            function_name = f'_process_{syscall.name}'

            # Process
            if hasattr(self, function_name):
                getattr(self, function_name)(syscall)

    def _default_process_path(self, s: Syscall):
        path = s.arguments[0].value.value
        proc_pid = f'/proc/{s.pid}'
        if path.startswith(proc_pid):
            s.arguments[0].value.value = '/proc/self' + path[len(proc_pid):]

    _process_open = _default_process_path
    _process_stat = _default_process_path

    def _default_process_at(self, s: Syscall):
        dir_fd = s.arguments[0].value.value
        path = s.arguments[1].value.value
        proc_pid = f'/proc/{s.pid}'

        if os.path.isabs(path) and path.startswith(proc_pid):
            s.arguments[1].value.value = '/proc/self' + path[len(proc_pid):]
        elif isinstance(dir_fd, str) and dir_fd.startswith(proc_pid):
            s.arguments[0].value.value = '/proc/self' + dir_fd[len(proc_pid):]

    _process_openat = _default_process_at


class PairPreprocessor(StracePreprocessor):
    """Pair strace preprocessor.

    A pair preprocessor accepts two strace objects for preprocessing.
    Preprocessors of this type are expected to potentially run multiple times
    during strace comparison.
    """

    def __call__(self, s1: Strace, s2: Strace, all_traces: Iterable[Strace]):
        """Preprocess an strace.

        Parameters
        ----------
        s1 : Strace
            First strace for preprocessing.
        s2 : Strace
            Second strace for preprocessing.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Activate custom syscall equality context and preprocess
        with self.syscall_equality():
            self._preprocess(s1, s2, all_traces)

    def _preprocess(self, s1: Strace, s2: Strace,
                    all_traces: Iterable[Strace]):
        """Preprocess a pair of straces.

        This is the main method for preprocessing. It must be implemented by
        a subclass and is expected to operate in place.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        raise NotImplementedError()


class StripLeadingSyscalls(PairPreprocessor):
    """Strip all similar leading syscalls.

    This preprocessor removes a shared prefix between two straces. All similar
    syscalls at the start of both straces are removed, up until the first
    non-similar syscall.
    """

    def _preprocess(self, s1: Strace, s2: Strace, *args, **kwargs):
        """Preprocess a pair of straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Pop leading syscalls
        while (s1.trace_lines
               and s2.trace_lines
               and s1.trace_lines[0] == s2.trace_lines[0]):
            s1.trace_lines.pop(0)
            s2.trace_lines.pop(0)


class StripTrailingSyscalls(PairPreprocessor):
    """Strip all similar trailing syscalls.

    This preprocessor removes a shared suffix between two straces. All similar
    syscalls at the end of both straces are removed, starting after the last
    non-similar syscall.
    """

    def _preprocess(self, s1: Strace, s2: Strace, *args, **kwargs):
        """Preprocess a pair of straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Iterable[Strace]
            All available traces. Preprocessing may use information from the
            global traces.
        """
        # Pop trailing syscalls
        while (s1.trace_lines
               and s2.trace_lines
               and s1.trace_lines[-1] == s2.trace_lines[-1]):
            s1.trace_lines.pop(-1)
            s2.trace_lines.pop(-1)
