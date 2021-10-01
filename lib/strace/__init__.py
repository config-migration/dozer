"""Strace support."""


# Imports
from functools import partial
from itertools import chain, groupby
from typing import (
    Any, Callable, Dict, Iterable, List, Optional, Set, Sequence, Union
)
import json
import pickle
import shutil

from sqlalchemy.sql import and_, cast, select
from sqlalchemy.sql.functions import count
from sqlalchemy.types import JSON

from lib import logger
from lib.strace import parser, util
from lib.strace.classes import (
    Strace, Syscall, StringLiteral
)
from lib.strace.classes import StraceJSONEncoder, from_object
from lib.strace.collection import (
    ansible_playbook, argument_holes, parameter_matching, untraced
)
from lib.strace.paths import (
    COMPUTED,
    STRACE,
    RAW_STRACES,
)
from lib.strace.tables import (
    metadata as t_metadata,
    executables as t_executables,
    straces as t_straces,
    argument_holes as t_argument_holes
)


# Types
StraceDict = Dict[Any, Union['StraceDict', List[Strace], Strace]]
StraceKeys = Sequence[Union[str, Callable[[Strace], Any]]]


# Collector Parsers
COLLECTORS = {
    'debops': ansible_playbook.parse_debops,
    'argument_holes': argument_holes.parse,
    'parameter_matching': parameter_matching.parse,
    'untraced': untraced.parse
}


class _Manager:
    """Strace manager.

    The manager is responsible for handling and abstracting all interaction
    between the strace knowledge base and client code.

    Due to the expense of parsing and deserializing traces, the manager makes
    extensive use of lazy loading and caching. This shouldn't be an issue
    unless the trace files present on the system change at runtime. If the
    this happens, and the manager needs the updated state, call
    manager.reset_cache().
    """

    def __init__(self):
        """Initialize an strace manager."""
        self._traces = {}
        self._holes = None

    def reset_cache(self):
        """Reset the manager strace cache."""
        self.__init__()

    def clean(self, raw: bool = None, parsed: bool = None):
        """Clean strace data.

        This removes strace files and all other parsed objects or data. If
        neither ``raw`` nor ``parsed`` are specified, both will be cleaned by
        default.

        Parameters
        ----------
        raw : bool
            If the manger should clean raw trace files.
        parsed : bool
            If the manager should clean parsed trace files.
        """
        # If neither argument is specified, set both true. All are cleaned
        # by default.
        if raw is None and parsed is None:
            raw = True
            parsed = True

        # Clean raw
        if raw:
            shutil.rmtree(RAW_STRACES)

        # Clean all parsed trace files.
        if parsed:
            strace_tables = (t_executables, t_straces, t_argument_holes)
            t_metadata.drop_all(tables=strace_tables)
            t_metadata.create_all(tables=strace_tables)

    def holes(self) -> Dict[str, Set[int]]:
        """Get all known syscall holes.

        Returns
        -------
        Dict[str, Set[int]]
            Mapping between syscalls and the indices of their arguments whose
            values can be considered holes.
        """
        if not self._holes:
            self._holes = {}
            for hole in t_argument_holes.select().execute():
                if hole.syscall not in self._holes:
                    self._holes[hole.syscall] = set()
                self._holes[hole.syscall].add(hole.index)
        return self._holes

    def trace_argument_holes(self):
        """Generate straces for argument holes."""
        argument_holes.collect()

    def trace_debops(self):
        """Generate debops traces."""
        ansible_playbook.collect_debops()

    def trace_parameter_matching(self):
        """Generate straces for parameter matching."""
        parameter_matching.collect()

    def trace_untraced(self, subset: Optional[list] = None):
        """Generate straces for untraced executables.

        Parameters
        ----------
        subset : Optional[list]
            List of executable definitions. Each object must have `system`,
            `executable`, and `arguments` attributes. If provided, untraced
            executables must also appear in this list.
        """
        untraced.collect(subset=subset)

    def generate_traces(self):
        """Generate all traces."""
        self.trace_argument_holes()
        self.trace_parameter_matching()
        self.trace_debops()
        self.trace_untraced()

    def traces(self, where: Optional = None) -> List[Strace]:
        """Load trace definitions.

        By default, this method deserializes and caches all known straces.
        Caching is performed by saving the strace ``id`` from the database.
        Because of caching, traces will only be deserialized once. Call
        ``self.reset_cache`` if traces need to be reloaded.

        Parameters
        ----------
        where : Optional
            An optional where clause compatible with sqlalchemy's select.where.
            If provided, the where clause will be used to limit the query for
            traces that will be deserialized.

        Returns
        -------
        Dict[str, Dict[str, List[Strace]]]
            All available traces, keyed by system and module.
        """
        # Query for traces
        query = (
            select([
                t_executables.c.system,
                t_executables.c.executable,
                t_executables.c.arguments,
                t_straces.c.id,
                t_straces.c.collector,
                t_straces.c.collector_assigned_id,
                t_straces.c.pickle,
            ])
            .select_from(t_executables.join(
                t_straces,
                t_executables.c.id == t_straces.c.executable
            ))
            .where(t_straces.c.id.notin_(set(self._traces.keys())))
        )

        # Apply where clause if provided
        if where is not None:
            query = query.where(where)

        # Execute the query
        res = query.execute()

        # Deserialize traces
        for trace in res:
            logger.info(
                f'Deserializing trace ({trace.collector}, {trace.system}, '
                f'{trace.executable}, {trace.arguments}, '
                f'{trace.collector_assigned_id})'
            )
            self._traces[trace.id] = from_object(trace)

        # Return the requested traces
        if where is not None:
            # Get all the ids that would have been in the original query,
            # including those that were already deserialized.
            res = (
                select([t_straces.c.id])
                .select_from(t_executables.join(
                    t_straces,
                    t_executables.c.id == t_straces.c.executable
                ))
                .where(where)
                .execute()
            )

            return [self._traces[trace.id] for trace in res]
        else:
            return list(self._traces.values())

    def traces_by(self,
                  keys: StraceKeys = (),
                  sort_keys: StraceKeys = (),
                  all_in_bin: bool = True,
                  traces: Optional[Iterable[Strace]] = None) -> StraceDict:
        """Bin traces by sets of nested keys.

        Parameters
        ----------
        keys : StraceKeys
            A sequence of keys used for binning. If the key is a string, it
            will be used as the name of an attribute from Strace. If the key
            is a callable, it will be passed the strace and must return a
            hashable object. Note that string valued keys must reference
            hashable attributes of the strace.
        sort_keys : StraceKeys
            A sequence of keys used for sorting. All individual bins returned
            will be sorted lexicographically by ``sort_keys``. The key must
            either be a string or a callable, the same as the ``keys`` param.
        all_in_bin : bool
            Whether all traces in a bin should be returned. If false, only a
            single strace object will be returned.
        traces : Optional[Iterable[Strace]]
            Optional list of traces to use for binning. If not provided, the
            global list of straces will be binned and returned.

        Returns
        -------
        StraceDict
            A potentially nested dictionary of straces. Keys are an attribute
            that the straces were binned by, and the value is either another
            dict of the same format, a list of strace objects, or a single
            strace object chosen from the set that would have been binned
            together.

            Straces are always binned by the executable key (system,
            executable, arguments) at the leaf level.
        """
        # Helper methods
        def _get_key(k, m):
            if callable(k):
                return key(m)
            else:
                return getattr(m, k)

        # Get traces.
        if traces is None:
            traces = self.traces()

        # Pick a single representative strace for each value of the last key
        # if we're not selecting all.
        if not all_in_bin and keys[-1]:

            # Start with no filtered traces
            filtered_trace_keys = set()
            filtered_traces = []

            logger.info('Filtering straces.')

            # Add first trace with each key to the filtered traces
            for strace in traces:
                key = _get_key(keys[-1], strace)
                if key not in filtered_trace_keys:
                    filtered_trace_keys.add(key)
                    filtered_traces.append(strace)

            # Replace traces
            traces = filtered_traces

        # Sort traces lexicographically
        logger.info('Sorting straces lexicographically.')
        for key in chain(reversed(sort_keys), reversed(keys)):
            _get_key_partial = partial(_get_key, key)
            traces = list(sorted(traces, key=_get_key_partial))

        # Form strace bins and track all current leaves.
        strace_bins = {'root': traces}
        leaves = [(strace_bins, 'root')]  # (parent, leaf name)

        # Bin by key
        logger.info('Binning straces.')
        for key in keys:

            # Create key getter
            _get_key_partial = partial(_get_key, key)

            # Process each available leaf
            for parent, name in leaves:

                # Replace bin with new sub bins
                parent[name] = {
                    k: list(v)  # Because the groupby iterator is dumb
                    for k, v in groupby(parent[name], key=_get_key_partial)
                }

            # Update leaves
            leaves = [
                (old_leaf_parent[old_leaf_name], new_leaf_name)
                for old_leaf_parent, old_leaf_name in leaves
                for new_leaf_name in old_leaf_parent[old_leaf_name]
            ]

        # Take single object if not selecting all.
        if not all_in_bin:
            for parent, name in leaves:
                parent[name] = parent[name][0]

        # Return binned traces
        return strace_bins['root']

    def parse(self, collectors: Set[str] = frozenset(COLLECTORS),
              start_at: Optional[Dict[str, str]] = None):
        """Parse available traces.

        This method will reset the manager, since the serialized traces are
        changing.

        Parameters
        ----------
        collectors : Set[str]
            Set of collectors to parse from. Defaults to all collectors.
        start_at : Optional[Dict[str, str]]
            Optional starting positions for parsing keyed by collector. Can
            be used to resume parsing.
        """
        self.reset_cache()
        self._parse(collectors, start_at)

    def _parse(self, collectors: Set[str] = frozenset(COLLECTORS),
               start_at: Optional[Dict[str, str]] = None):
        """Parse all available traces.

        Parameters
        ----------
        collectors : Set[str]
            Set of collectors to parse from. Defaults to all collectors.
        start_at : Optional[Dict[str, str]]
            Optional starting positions for parsing keyed by collector. Can
            be used to resume parsing.
        """
        # Normalize names
        collectors = set(c.replace('-', '_') for c in collectors)

        # Default start at if not provided
        if start_at is None:
            start_at = {}

        # Iterator for all parsed traces
        traces = chain.from_iterable(
            collector_parser(start_at=start_at.get(collector, None))
            for collector, collector_parser in COLLECTORS.items()
            if collector in collectors
        )

        # Add to database
        for strace in traces:

            # Normalize the trace. The collector should normalize its straces
            # when it parses them, but normalizing an already normalized strace
            # is a noop, so it doesn't hurt us to check.
            strace = strace.normalize()

            # Add the trace to the database
            self.idempotent_add_strace(strace)

    def find_holes(self):
        """Find all syscall argument holes."""
        logger.info('Finding syscall argument holes.')

        # Query for matching straces
        with_multi_strace = (
            select([t_straces]).where(
                t_straces.c.executable.in_(
                    select([t_straces.c.executable])
                    .group_by(t_straces.c.executable)
                    .having(count() > 1)
                )
            )
            .cte('multi_strace')
        )
        q_exe_with_multi_strace = (
            select([
                t_executables.c.system,
                t_executables.c.executable,
                t_executables.c.arguments,
                with_multi_strace.c.collector,
                with_multi_strace.c.collector_assigned_id,
                with_multi_strace.c.pickle,
            ])
            .select_from(
                t_executables.join(
                    with_multi_strace,
                    t_executables.c.id == with_multi_strace.c.executable
                )
            )
        )

        # Run query to collect all strace objects
        logger.info('Querying for and parsing strace objects.')
        straces = list(map(
            from_object,
            q_exe_with_multi_strace.execute()
        ))

        # Bin straces by executable
        logger.info('Binning by executable.')
        groups = {}
        for strace in straces:
            key = strace.executable_key
            if key not in groups:
                groups[key] = []
            groups[key].append(strace)

        logger.info('Finding holes.')
        holes = argument_holes.find_holes(groups.values())

        logger.info('Recording discovered holes')
        for syscall, indices in holes.items():
            for index in indices:
                self.idempotent_add_hole(syscall, index)

    def idempotent_add_executable(self, strace: Strace) -> int:
        """Ensure an traced executable is stored by the manager.

        Parameters
        ----------
        strace : Strace
            Strace object.

        Returns
        -------
        int
            Executable id.
        """
        # Get sha1 hash for arguments
        arguments_sha1 = strace.arguments_hash

        # Executable query
        q_executable = t_executables.select().where(and_(
            t_executables.c.system == strace.system,
            t_executables.c.executable == strace.executable,
            t_executables.c.arguments_hash == arguments_sha1,
            t_executables.c.arguments == cast(
                strace.arguments, JSON
            ),
        ))

        # Query for an existing executable
        executable = q_executable.execute().first()

        # Return the executable id if it already exists
        if executable:
            return executable.id

        logger.info(
            f'Adding executable ({strace.system}, '
            f'{strace.executable}, {strace.arguments}) to the '
            f'database'
        )

        # Create the executable if it does not exist.
        insert = (
            t_executables.insert({
                'system': strace.system,
                'executable': strace.executable,
                'arguments_hash': arguments_sha1,
                'arguments': strace.arguments,
            })
            .execute()
        )

        # Return executable id
        return insert.inserted_primary_key

    def idempotent_add_strace(self, strace: Strace) -> int:
        """Ensure an strace is stored by the manager.

        Parameters
        ----------
        strace : Strace
            Strace object.

        Returns
        -------
        int
            Strace id.
        """
        # Add executable if it does not already exist
        # Get executable id
        executable_id = self.idempotent_add_executable(strace)

        # Query for existing strace
        existing_strace = (
            t_straces.select().where(and_(
                t_straces.c.collector == strace.collector,
                t_straces.c.collector_assigned_id
                == strace.collector_assigned_id,
            ))
            .execute()
            .first()
        )

        # If the strace exists, validate it belongs to the correct executable
        if existing_strace:
            if existing_strace.executable != executable_id:
                raise Exception(
                    f'An strace with the key ({strace.collector}, '
                    f'{strace.collector_assigned_id}) already exists and '
                    f'has a different executable.'
                )
            logger.info(f'Existing strace found with id {existing_strace.id}')
            return existing_strace.id

        logger.info(
            f'Adding strace ({strace.collector}, '
            f'{strace.collector_assigned_id}) to strace database'
        )

        # Get original strace text
        with open(strace.strace_file, 'r') as fd:
            strace_text = fd.read()

        # Create new strace
        insert = (
            t_straces.insert({
                'executable': executable_id,
                'collector': strace.collector,
                'collector_assigned_id': strace.collector_assigned_id,
                'strace': strace_text,
                'metadata': strace.metadata,
                'json': json.loads(json.dumps(strace, cls=StraceJSONEncoder)),
                'pickle': pickle.dumps(strace)
            })
            .execute()
        )

        # Return primary key
        return insert.inserted_primary_key

    def idempotent_add_hole(self, syscall: str, index: int) -> int:
        """Add a syscall hole.

        Parameters
        ----------
        syscall : str
            Syscall name.
        index : int
            Hole argument index.

        Returns
        -------
        int
            Primary key of the inserted argument hole.
        """
        # Query for an existing hole record
        hole = (
            select([t_argument_holes.c.id]).where(and_(
                t_argument_holes.c.syscall == syscall,
                t_argument_holes.c.index == index
            ))
            .execute()
            .first()
        )

        # If it existed, return it.
        if hole:
            return hole.id

        # If not defined, insert it.
        insert = (
            t_argument_holes.insert({
                'syscall': syscall,
                'index': index,
            })
            .execute()
        )

        # Return inserted key
        return insert.inserted_primary_key


manager = _Manager()
