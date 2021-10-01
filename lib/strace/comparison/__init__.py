"""Strace comparison functionality."""


# Imports
from typing import Iterable

from sqlalchemy.sql import or_

from lib import logger
from lib.strace import manager
from lib.strace.classes import RestoreCheckpoint
from lib.strace.comparison.preprocessing import (
    AnsibleStripLastWrite,
    ReplaceFileDescriptors,
    ReplacePIDInLockFiles,
    ReplacePIDInProcfs,
    PunchHoles,
    SelectSyscalls,
    GenerateSyntheticValues,
    SinglePreprocessor,
    StripLeadingSyscalls,
    StripTrailingSyscalls,
    StripGlobalSyscalls,
)
from lib.strace.comparison.scoring import (
    ScoringMethod,
    JaccardCoefficient,
    MaximumCardinalityMatching,
    NormalizedInformationContent,
    TFIDF,
    TFIDFMaximumWeightedMatching,
)
from lib.strace.comparison.syscall_equality import (
    CanonicalEquality,
    NameEquality,
    StrictEquality,
)
from lib.strace.comparison.scoring import ScoringResult


# Defaults
DEFAULT_SINGLE_PREPROCESSORS = [
    SelectSyscalls(),
    ReplacePIDInLockFiles(),
    ReplacePIDInProcfs(),
    AnsibleStripLastWrite(),
    GenerateSyntheticValues(),
]
DEFAULT_PAIR_PREPROCESSORS = [
    StripLeadingSyscalls(syscall_equality=NameEquality()),
    StripTrailingSyscalls(syscall_equality=NameEquality()),
    StripGlobalSyscalls(syscall_equality=NameEquality())
]
DEFAULT_SYSCALL_EQUALITY = CanonicalEquality()


# Standard scoring methods
compare_mcm = MaximumCardinalityMatching(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_PAIR_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY,
)
compare_mcwm = TFIDFMaximumWeightedMatching(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_PAIR_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY,
    maxcardinality=True,
    tfidf_syscall_equality=DEFAULT_SYSCALL_EQUALITY,
)
compare_mwm = TFIDFMaximumWeightedMatching(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY,
    maxcardinality=False,
    tfidf_syscall_equality=DEFAULT_SYSCALL_EQUALITY,
)
compare_nic = NormalizedInformationContent(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_PAIR_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY
)
compare_nic_no_preprocessing = NormalizedInformationContent(
    syscall_equality=DEFAULT_SYSCALL_EQUALITY
)
compare_jc = JaccardCoefficient(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_PAIR_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY
)
compare_tfidf = TFIDF(
    single_preprocessors=DEFAULT_SINGLE_PREPROCESSORS,
    pair_preprocessors=DEFAULT_PAIR_PREPROCESSORS,
    syscall_equality=DEFAULT_SYSCALL_EQUALITY
)

# Default comparison function
compare = compare_nic
compare_no_preprocessing = compare_nic_no_preprocessing


@RestoreCheckpoint()
def load_and_compare(s1, s2, load=False,
                     by: ScoringMethod = compare_no_preprocessing,
                     global_preprocessors: Iterable[SinglePreprocessor] =
                     DEFAULT_SINGLE_PREPROCESSORS
                     ) -> Iterable[Iterable[ScoringResult]]:
    """Load and compare two or more straces.

    Parameters
    ----------
    s1
        Where clause compatible with sqlalchemy's ``select.where``. This where
        clause will be used to load the first set of strace definitions, which
        will be compared to those in s2.
    s2
        Where clause compatible with sqlalchemy's ``select.where``. This where
        clause will be used to load the second set of strace definitions, which
        those from s1 will be compared to.
    load
        Where clause compatible with sqlalchemy's ``select.where``. This where
        clause will be used to load any additional strace definitions to be
        used during comparison (may impact preprocessors or scoring methods)
        that consider the global strace information. If ``load=False``, no
        additional straces will be loaded. If ``load=True``, all straces will
        be loaded.
    by : ScoringMethod
        Scoring method to perform comparison by. If not specified, the
        default scoring method ``comparision.compare_no_preprocessing``
        will be used.
    global_preprocessors : Iterable[SinglePreprocessor]
        Preprocessors to apply globally prior to scoring.

    Returns
    -------
    Iterable[Iterable[ScoringResult]]
        All scoring results for s1 into s2 (cross-product).
    """
    # Load traces.
    logger.info('Loading traces...')
    s1_traces = manager.traces(where=s1)
    s2_traces = manager.traces(where=s2)
    if load is False:
        all_traces = manager.traces(where=or_(s1, s2))
    elif load is True:
        all_traces = manager.traces()
    else:
        all_traces = manager.traces(where=or_(s1, s2, load))
    logger.info('Done loading traces.')

    # Preprocess.
    logger.info('Preprocessing...')
    for preprocessor in global_preprocessors:
        for trace in all_traces:
            preprocessor(trace, all_traces=all_traces)
    logger.info('Done preprocessing.')

    # Compare
    logger.info('Comparing traces...')
    results = []
    for s1_trace in s1_traces:

        # Compare s1_trace to all s2 traces
        s1_results = [
            by(s1_trace, s2_trace, all_traces=all_traces)
            for s2_trace in s2_traces
        ]

        # Normalize score
        max_score = max(result.score for result in s1_results)
        for result in s1_results:
            if max_score != 0:
                result.normalized_score = result.score / max_score
            else:
                result.normalized_score = 0

        # Append results
        results.append(s1_results)
    logger.info('Done comparing traces.')

    # Return comparison results
    return results
