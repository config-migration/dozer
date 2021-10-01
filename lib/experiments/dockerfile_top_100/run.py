"""Dockerfile Top N experiment.

This experiment takes the top N most common (executable, arguments) pairs from
collected Dockerfiles and finds the Ansible modules with the highest similarity
scores.
"""


# Imports.
from typing import List, Tuple

from sqlalchemy.sql import or_

from lib import logger
from lib.experiments.dockerfile_top_100.data import (
    COLLECTOR_NAME as DOCKERFILE_COLLECTOR,
    DOCKERFILE_EXECUTABLES,
    SYSTEM as DOCKERFILE_SYSTEM,
)
from lib.strace import manager, search
from lib.strace.classes import MigrationResult, RestoreCheckpoint, Strace
from lib.strace.collection.ansible_playbook import (
    COLLECTOR_NAME as ANSIBLE_PLAYBOOK_COLLECTOR
)
from lib.strace.comparison.preprocessing import (
    AnsibleStripLastWrite,
    GenerateSyntheticValues,
    ReplacePIDInLockFiles,
    ReplacePIDInProcfs,
    SelectSyscalls,
)
from lib.strace.comparison.scoring import (
    NormalizedInformationContent,
    JaccardCoefficient,
    ScoringResult
)
from lib.strace.comparison.syscall_equality import (
    CanonicalEquality,
    StrictEquality
)
from lib.strace.tables import straces as t_straces
from lib.validation.docker import ValidationResult


# Comparison objects.
compare_nic = NormalizedInformationContent(
    syscall_equality=CanonicalEquality()
)
compare_jc = JaccardCoefficient(syscall_equality=StrictEquality())
preprocessors = (
    SelectSyscalls(),
    ReplacePIDInLockFiles(),
    ReplacePIDInProcfs(),
    AnsibleStripLastWrite(),  # TODO Remove this?
    GenerateSyntheticValues(),
)


@RestoreCheckpoint()
def run(server: int = 1,
        of: int = 1,
        baseline: bool = False) -> List[Tuple[Strace, List[ScoringResult]]]:
    """Run experiment.

    Parameters
    ----------
    server : int
        Server number (one-indexed). This option is intended for distributing
        analysis among multiple servers. If it is specified, the experiment
        will start with the ith dockerfile trace. This option must be specified
        with the ``of`` option.
    of : int
        Number of servers (one-indexed). This option is intended for
        distributing analysis among multiple servers. If it is specified, the
        experiment will process every ith dockerfile trace. This option must
        be specified with the ``server`` option.
    baseline : bool
        Run the baseline experiment. The baseline is run with the same dataset,
        but does not do any preprocessing and compares straces using the
        Jaccard Coefficient scoring method with strict syscall equality.

    Returns
    -------
    List[Tuple[Strace, List[ScoringResult]]]
        List of (trace, results) pairs for each known dockerfile trace. The
        comparison results for each trace are sorted in descending order by
        score (best match first).
    """
    # Validate options.
    if server > of:
        raise ValueError(
            'Server number cannot be bigger than the number of servers.'
        )

    logger.info('Starting Dockerfile Top 100 experiment.')

    # Get correct scoring method.
    if baseline:
        logger.info(f'Running as baseline.')
        compare = compare_jc
    else:
        compare = compare_nic
    logger.info(f'Using comparison method `{compare.__class__.__name__}`.')

    # Trace executables.
    manager.trace_untraced(subset=DOCKERFILE_EXECUTABLES)
    manager.parse(collectors={'untraced'})

    # Log stats and filter.
    num_executables = len(DOCKERFILE_EXECUTABLES)
    num_filtered = 100 - num_executables
    logger.info(
        f'\n'
        f'Dockerfile executable stats:\n'
        f'    {num_filtered} executables filtered from top 100.\n'
        f'    {num_executables} executables will be used.'
    )
    dockerfile_executable_tuples = list(
        (exe.executable, exe.arguments)
        for exe in DOCKERFILE_EXECUTABLES
    )

    # Load all traces.
    logger.info('Loading traces...')
    traces = manager.traces(where=or_(
        t_straces.c.collector == ANSIBLE_PLAYBOOK_COLLECTOR,
        t_straces.c.collector == DOCKERFILE_COLLECTOR,
    ))
    logger.info('Done loading traces.')

    # Bin and get experiment traces.
    logger.info('Binning traces by system...')
    traces_by_system = manager.traces_by(
        keys=('system',),
        sort_keys=('collector_assigned_id',),
        traces=traces
    )
    logger.info('Done binning traces by system.')

    ansible_traces = traces_by_system['ansible']
    logger.info(f'{len(ansible_traces)} ansible traces loaded.')

    logger.info('Binning dockerfile system traces by collector...')
    dockerfile_system_traces_by_collector = manager.traces_by(
        keys=('collector',),
        traces=traces_by_system[DOCKERFILE_SYSTEM]
    )
    logger.info('Done binning dockerfile system traces by collector.')

    dockerfile_traces = list(
        trace
        for trace in dockerfile_system_traces_by_collector[
            DOCKERFILE_COLLECTOR
        ]
        if (trace.executable, trace.arguments) in dockerfile_executable_tuples
    )
    logger.info(f'{len(dockerfile_traces)} dockerfile traces loaded.')

    # Preprocess if not baseline.
    if not baseline:
        logger.info('Preprocessing...')
        for preprocessor in preprocessors:
            for trace in traces:
                preprocessor(trace, all_traces=traces)
        logger.info('Done preprocessing.')

    # Compute similarity scores.
    logger.info('Computing similarity scores...')
    dockerfile_results = []
    for dockerfile_trace in dockerfile_traces[server - 1::of]:

        # List of results just for this dockerfile trace.
        trace_results = []

        # Compare against all available ansible traces.
        for ansible_trace in ansible_traces:

            # Run comparison.
            trace_results.append(compare(
                dockerfile_trace,
                ansible_trace,
                all_traces=traces,
            ))

        # Sort trace results in descending order by score and append
        # to the overall results.
        trace_results = sorted(trace_results, reverse=True)

        # Normalize trace result scores.
        max_trace_score = max(res.score for res in trace_results)
        for res in trace_results:
            res.normalized_score = res.score / max_trace_score

        # Append final results
        dockerfile_results.append((dockerfile_trace, trace_results))
    logger.info('Done computing similarity scores.')

    # Return final results for all dockerfile traces.
    return dockerfile_results


def postprocess(results: List[Tuple[Strace, List[ScoringResult]]]) -> List[
        Tuple[MigrationResult, ValidationResult]]:
    """Postprocess scoring results.

    Parameters
    ----------
    results : List[Tuple[Strace, List[ScoringResult]]]
        Results as returned by ``run``.

    Returns
    -------
    Tuple[MigrationResult, ValidationResult]]
    """
    # Process each set of results.
    search_results = []
    for strace, scores in results:

        logger.info(f'Postprocessing: {strace.executable_repr}')

        try:
            # Get setup used for original executable tracing.
            setup = next(
                exe
                for exe in DOCKERFILE_EXECUTABLES
                if (exe.system == strace.system
                    and exe.executable == strace.executable
                    and exe.arguments == strace.arguments)
            ).setup
            search_result = search.search_for_migration(
                strace, scores, setup=setup
            )
            if search_result is None:
                logger.warning(
                    f'No migrations were returned while postprocessing '
                    f'`{strace.executable_repr}`, it will not be included in '
                    f'results.'
                )
            else:
                search_results.append(search_result)
        except Exception:
            logger.exception(
                f'Encountered exception while postprocessing '
                f'`{strace.executable_repr}`, it will not be included in '
                f'results'
            )

    return search_results
