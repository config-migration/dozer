"""Cross product experiment.

This experiment computes a matching for every pair in the cross product of
LINUX_STRACES x ANSIBLE_STRACES. The results are output as a pandas dataframe.
"""


# Imports
from typing import List, Tuple

from pandas import DataFrame

from lib import logger
from lib.strace import manager
from lib.strace.classes import ParameterMapping, RestoreCheckpoint, Strace
from lib.strace.comparison.preprocessing import (
    AnsibleStripLastWrite,
    GenerateSyntheticValues,
    ReplacePIDInLockFiles,
    ReplacePIDInProcfs,
    SelectSyscalls,
)
from lib.strace.comparison.scoring import NormalizedInformationContent
from lib.strace.comparison.syscall_equality import CanonicalEquality
from lib.strace.collection.parameter_matching import (
    COLLECTOR_NAME as PARAMETER_MATCHING
)
from lib.strace.tables import straces as t_straces


# Comparison strategy
# from lib.strace.comparison.scoring import MaximumCardinalityMatching
# compare = MaximumCardinalityMatching(syscall_equality=CanonicalEquality())
compare = NormalizedInformationContent(syscall_equality=CanonicalEquality())

# Preprocessors
preprocessors = [
    SelectSyscalls(),
    ReplacePIDInLockFiles(),
    ReplacePIDInProcfs(),
    GenerateSyntheticValues(),
]


@RestoreCheckpoint()
def run(collector: str = PARAMETER_MATCHING) -> Tuple[
            DataFrame,
            List[Tuple[Strace, Strace, ParameterMapping]]
        ]:
    """Run cross-product experiment.

    Parameters
    ----------
    collector : str
        Name of a collector that provides Ansible and Linux straces. A
        comparison will be made for all pairs of straces in the cross product
        of straces from both systems.

    Returns
    -------
    DataFrame
        n x m DataFrame of comparison scores.
    List[Tuple[Strace, Strace, ParameterMapping]]
        Strace and parameter mapping for all pairs where the parameter mapping
        was non-empty.
    """
    # Log start
    logger.info('Starting cross-product experiment.')

    # Parse all traces
    logger.info('Loading traces.')
    all_traces = manager.traces(where=t_straces.c.collector == collector)

    # Preprocess
    logger.info('Performing global preprocessing')
    for trace in all_traces:
        for preprocessor in preprocessors:
            preprocessor(trace, all_traces=all_traces)

    # Group traces
    logger.info('Grouping loaded traces.')
    collector_traces = manager.traces_by(
        keys=('collector', 'system', 'executable_key',),
        sort_keys=('collector_assigned_id',),
        all_in_bin=False,
        traces=all_traces
    )[collector]
    executable_all_traces = set(
        manager.traces_by(
            keys=('executable_key',),
            all_in_bin=False,
            traces=all_traces
        ).values()
    )

    # Get strace values for linux and ansible. Sort them by executable for
    # easy display and comparison.
    linux_traces = list(sorted(
        collector_traces['linux'].values(),
        key=lambda s: s.collector_assigned_id
    ))
    ansible_traces = list(sorted(
        collector_traces['ansible'].values(),
        key=lambda s: s.collector_assigned_id
    ))

    # Get row and col names
    rows = list(map(lambda m: m.collector_assigned_id, linux_traces))
    cols = list(map(lambda m: m.collector_assigned_id, ansible_traces))

    # Init scores dictionary
    scores = {r: [] for r in rows}
    mappings = []

    # Compute score for each pair of (linux, ansible) traces
    logger.info('Starting strace comparison.')
    for row, linux_strace in zip(rows, linux_traces):
        row_max = -1
        row_max_mapping = None
        for ansible_strace in ansible_traces:
            # Log
            ids = (
                linux_strace.collector_assigned_id,
                ansible_strace.collector_assigned_id
            )
            linux_key = (linux_strace.executable, linux_strace.arguments)
            ansible_key = (ansible_strace.executable, ansible_strace.arguments)
            logger.info(
                f'\n'
                f'    Comparing traces for: {ids}\n'
                f'    Linux:   {linux_key}\n'
                f'    Ansible: {ansible_key}'
            )

            # Compute score.
            result = compare(
                linux_strace,
                ansible_strace,
                all_traces=executable_all_traces
            )
            scores[row].append(result.score)

            # Save score and associated mapping if better than the previous
            if result.score > row_max:
                row_max = result.score
                if result.mapping:
                    row_max_mapping = (
                        linux_strace, ansible_strace, result.mapping
                    )
                else:
                    row_max_mapping = None

        # If row had a max mapping
        if row_max_mapping:
            mappings.append(row_max_mapping)

    # Log finish and return dataframe containing scores.
    logger.info('Cross-product experiment finished.')
    return DataFrame.from_dict(scores, orient='index', columns=cols), mappings
