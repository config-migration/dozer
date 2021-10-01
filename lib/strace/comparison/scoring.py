"""Comparison scoring for straces."""


# Imports
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import reduce
from itertools import chain, product
from typing import Dict, List, Optional, Set, Tuple
import math
import operator

import networkx as nx

from lib import logger
from lib.strace.classes import (
    ParameterMapping, RestoreCheckpoint, Strace, ExecutableParameter, Syscall
)
from lib.strace.comparison.preprocessing import (
    SinglePreprocessor,
    PairPreprocessor,
)
from lib.strace.comparison.syscall_equality import (
    SyscallEquality,
    StrictEquality,
)


@dataclass(order=True)
class ScoringResult:
    """The result of comparing two straces.

    This is a container class holding the result of comparing ``s1`` to ``s2``.
    The score and parameter mapping should be provided comparison, and the
    normalized_score may be set if any additional normalization is done.
    Results have a total ordering based on score.

    A parameter mapping is a list of mapped executable argument keys. Mappings
    are guaranteed to be in the order (s1 key, s2 key).
    """
    score: float
    normalized_score: Optional[float] = field(compare=False)
    s1: Strace = field(compare=False)
    s2: Strace = field(compare=False)
    mapping: ParameterMapping = field(compare=False)


class ScoringMethod:
    """Scoring method."""

    def __init__(self,
                 single_preprocessors:
                 Optional[List[SinglePreprocessor]] = None,
                 pair_preprocessors: Optional[List[PairPreprocessor]] = None,
                 syscall_equality: SyscallEquality = StrictEquality()):
        """Initialize a new scoring method.

        Parameters
        ----------
        single_preprocessors : Optional[List[SinglePreprocessor]]
            Single preprocessors to run during scoring.
        pair_preprocessors : Optional[List[PairPreprocessor]]
            Pair preprocessors to run during scoring.
        syscall_equality : SyscallEquality
            Syscall equality metric.
        """
        self.single_preprocessors = single_preprocessors or []
        self.pair_preprocessors = pair_preprocessors or []
        self.syscall_equality = syscall_equality

    def __call__(self,
                 s1: Strace,
                 s2: Strace,
                 all_traces: Set[Strace]) -> ScoringResult:
        """Compute a comparison score for two straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        ScoringResult

        """
        logger.info(f'Comparing {s1.executable_repr} => {s2.executable_repr}')

        # Activate the equality and restore context
        with self.syscall_equality(), RestoreCheckpoint():

            # Preprocess
            logger.info('Preprocessing.')
            self._preprocess(s1, s2, all_traces)

            # Return 1 for exact match if either was preprocessed out.
            if not s1.trace_lines or not s2.trace_lines:
                logger.info('Preprocessing removed all syscalls.')
                logger.info('Score: 1')
                return ScoringResult(1, None, s1, s2, [])

            # If both straces have executable parameters, map them together
            # before computing the similarity score.
            parameter_key_mapping = []
            if (hasattr(s1, 'executable_parameters')
                    and hasattr(s2, 'executable_parameters')):
                logger.info('Generating executable parameter mapping.')
                parameter_mapping = self._map_parameters(s1, s2)
                for value1, value2 in parameter_mapping:
                    ExecutableParameter.map_values(value1, value2)
                    parameter_key_mapping.append((value1.key, value2.key))
            else:
                parameter_mapping = []

            # Compute score
            with ExecutableParameter.compare_by_map():
                logger.info('Scoring...')
                logger.debug_strace(s1)
                logger.debug_strace(s2)
                score = self._score(s1, s2, all_traces)
                logger.info(f'Score: {score}')

            # Unmap executable parameters.
            for value1, value2 in parameter_mapping:
                ExecutableParameter.unmap_values(value1, value2)

            # Return scoring result.
            return ScoringResult(score, None, s1, s2, parameter_key_mapping)

    def _preprocess(self,
                    s1: Strace,
                    s2: Strace,
                    all_traces: Set[Strace]):
        """Preprocess straces in-place.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces
        """
        # Log
        logger.debug(
            f'Syscalls before preprocessing: '
            f'({len(s1.trace_lines)}, {len(s2.trace_lines)})'
        )

        # Run single preprocessors
        for preprocessor in self.single_preprocessors:
            preprocessor(s1)
            preprocessor(s2)
            for strace in all_traces:
                preprocessor(strace, all_traces)

        # Run pair preprocessors
        for preprocessor in self.pair_preprocessors:
            preprocessor(s1, s2, all_traces)

        # print(s1.trace_lines)

        # Log
        logger.debug(
            f'Syscalls after preprocessing: '
            f'({len(s1.trace_lines)}, {len(s2.trace_lines)})'
        )

    def _map_parameters(self,
                        s1: Strace,
                        s2: Strace) -> List[Tuple[
                            ExecutableParameter, ExecutableParameter
                        ]]:
        """Generate a mapping of executable parameters.

        Parameters
        ----------
        s1 : Strace
            First strace.
        s2 : Strace
            Second strace.

        Returns
        -------
        List[Tuple[ExecutableParameter, ExecutableParameter]]
            All mapped executable parameters. Tuples are guaranteed to be
            ordered with (s1 value, s2 value).
        """
        # All syscalls with executable parameters
        logger.debug('Getting syscalls with executable parameters.')
        s1_syscalls = [
            s for s in s1.trace_lines if hasattr(s, 'executable_parameters')
        ]
        s2_syscalls = [
            s for s in s2.trace_lines if hasattr(s, 'executable_parameters')
        ]
        logger.debug(
            f'{len(s1_syscalls)} syscalls with executable parameters from '
            f'{s1.executable_repr}'
        )
        logger.debug(
            f'{len(s2_syscalls)} syscalls with executable parameters from '
            f'{s2.executable_repr}'
        )

        # Get all pairs of syscalls that compare the same if the executable
        # parameters match.
        with ExecutableParameter.compare_equal():
            logger.debug('Getting equivalent syscall pairs')
            syscall_pairs = [
                (syscall1, syscall2)
                for syscall1, syscall2 in product(s1_syscalls, s2_syscalls)
                if syscall1 == syscall2
            ]
            logger.debug(f'{len(syscall_pairs)} syscall pairs found')

        # Activate compare by id context so all synthetic values appear unique.
        with ExecutableParameter.compare_by_id():

            # From all pairs, get only those that do not compare equal if the
            # synthetic values are different.
            logger.debug(
                'Filtering to syscall pairs affected by synthetic values'
            )
            syscall_pairs = [
                (syscall1, syscall2)
                for syscall1, syscall2 in syscall_pairs
                if syscall1 != syscall2
            ]
            logger.debug(f'{len(syscall_pairs)} affected pairs found')

            # Return no matched pairs if no affected syscalls were found
            if not syscall_pairs:
                logger.info('No parameters mapped.')
                return []

            # Unpack pairs into s1/s2 tuples
            s1_syscalls, s2_syscalls = zip(*syscall_pairs)

            # Get all executable parameters used in the identified pairs
            s1_parameters = list(reduce(
                operator.or_,
                map(lambda s: set(s.executable_parameters), s1_syscalls)
            ))
            s2_parameters = list(reduce(
                operator.or_,
                map(lambda s: set(s.executable_parameters), s2_syscalls)
            ))

        # Lookup dictionary of all values by their id.
        s1_values_by_id = {id(v): v for v in s1_parameters}
        s2_values_by_id = {id(v): v for v in s2_parameters}

        def ordered_values_by_id(id1, id2):
            try:
                return s1_values_by_id[id1], s2_values_by_id[id2]
            except KeyError:
                return s1_values_by_id[id2], s2_values_by_id[id1]

        # Benefits for mapping v1 = v2. Keyed by value unique ids.
        mapping_benefit = defaultdict(lambda: 0)

        # Activate compare by map context so that mapped parameters only
        # compare equal to each other.
        with ExecutableParameter.compare_by_map():

            # Test all pairs of values
            logger.debug('Computing benefit for value pairs')
            for param1, param2 in product(s1_parameters, s2_parameters):

                logger.debug(
                    f'Computing benefit for:\n'
                    f'    {param1}\n'
                    f'    {param2}'
                )

                # Map parameters. They will only compare equal to each other.
                # Unmapped parameters will still compare equal to all other
                # unmapped parameters.
                ExecutableParameter.map_values(param1, param2)

                # Test all syscall pairs whose equality is affected by
                # synthetic values. If the syscalls contain both values and
                # compare as equal with the mapping, then compute and store
                # the additional benefit of the mapping.
                for syscall1, syscall2 in syscall_pairs:

                    # Get the number of times value1 and value2 occur in
                    # syscall1 and syscall2, respectively.
                    p1_count = sum(
                        1
                        for v in syscall1.executable_parameters
                        if v is param1
                    )
                    p2_count = sum(
                        1
                        for v in syscall2.executable_parameters
                        if v is param2
                    )

                    # If param1 and param2 have nonzero counts and
                    # syscall1 == syscall2 because of the mapping, then add
                    # to the mapping benefit.
                    if p1_count and p2_count and syscall1 == syscall2:

                        # Compute benefit
                        # The mapping benefit is defined as the total portion
                        # of the match that the values are responsible for.
                        # This is guaranteed to be in the range 0..1. It might
                        # be less than 1 if multiple synthetic values appear
                        # in a single syscall.
                        s1_count = len(syscall1.executable_parameters)
                        s2_count = len(syscall2.executable_parameters)
                        benefit = (p1_count + p2_count) / (s1_count + s2_count)

                        # Add additional weight to the mapping benefit
                        mapping_benefit[(id(param1), id(param2))] += benefit

                # Unmap values.
                ExecutableParameter.unmap_values(param1, param2)

        # Construct matching graph
        logger.debug('Constructing matching graph')
        g = nx.Graph()
        for (id1, id2), benefit in mapping_benefit.items():
            g.add_edge(id1, id2, weight=benefit)

        # Compute the maximum weight maximum cardinality matching between
        # parameters.
        logger.debug('Computing matching between executable parameters')
        return [
            ordered_values_by_id(id1, id2)
            for id1, id2 in nx.max_weight_matching(g, maxcardinality=True)
        ]

    def _score(self,
               s1: Strace,
               s2: Strace,
               all_traces: Set[Strace]) -> float:
        """Compute a comparison score for two straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        raise NotImplementedError()


class MaximumMatching(ScoringMethod):
    """A comparison method based on computing a maximum matching."""

    def _score(self,
               s1: Strace,
               s2: Strace,
               all_traces: Set[Strace]) -> float:
        """Compute a comparison score for two straces by using a matching.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        # Label syscalls
        s1_syscalls = list(map(
            lambda v: ('s1', v[0], v[1]),
            enumerate(s1.trace_lines)
        ))
        s2_syscalls = list(map(
            lambda v: ('s2', v[0], v[1]),
            enumerate(s2.trace_lines)
        ))

        # Create a networkx graph.
        g = nx.Graph()

        # Buckets of all syscalls that are potentially equal
        s1_buckets = {}
        s2_buckets = {}

        # Bucket s1 syscalls
        for syscall in s1_syscalls:
            _, _, call = syscall
            key = hash(call)
            if key not in s1_buckets:
                s1_buckets[key] = []
            s1_buckets[key].append(syscall)

        # Bucket s2 syscalls
        for syscall in s2_syscalls:
            _, _, call = syscall
            key = hash(call)
            if key not in s2_buckets:
                s2_buckets[key] = []
            s2_buckets[key].append(syscall)

        # Find the smallest and largest buckets.
        if len(s1_buckets) <= len(s2_buckets):
            smallest, largest = s1_buckets, s2_buckets
        else:
            smallest, largest = s2_buckets, s1_buckets

        # Compare all syscalls in buckets with the same key. Add an edge
        # between them if they are equal. This implicitly adds vertices
        # to the graph if they were not already present. The resulting
        # graph should only have vertices that participate in edges.
        for key in smallest:
            if key not in largest:
                continue
            for syscall1, syscall2 in product(smallest[key], largest[key]):
                _, _, call1 = syscall1
                _, _, call2 = syscall2
                if call1 == call2:
                    g.add_edge(syscall1, syscall2)

        # Compute a maximum matching in g
        matching = self._matching(g, s1_syscalls, s2_syscalls, all_traces)
        logger.debug(f'Size of matching: {len(matching)}')

        # from lib.strace.comparison.canonical_form import canonical_repr
        # with canonical_repr():
        #     all_matched = set(chain.from_iterable(matching))
        #     s1_set = set(s1_syscalls)
        #     s1_unmatched = s1_set - all_matched
        #
        #     print(s1_unmatched)
        #     print(matching)

        # Score.
        score = self._matching_score(
            matching, g, s1_syscalls, s2_syscalls, all_traces
        )
        return score

    def _matching(self,
                  g: nx.Graph,
                  s1_syscalls: List[Tuple[str, str, Syscall]],
                  s2_syscalls: List[Tuple[str, str, Syscall]],
                  all_traces: Set[Strace]
                  ) -> Set[Tuple[Syscall, Syscall]]:
        """Compute a matching in g.

        Implementations of this method are expected to use the graph g to
        generate a matching, although may make modifications based on
        either syscall or other traces if necessary.

        Parameters
        ----------
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All other available traces.

        Returns
        -------
        Set[Tuple[Syscall, Syscall]]
            Set of matched syscall pairs.
        """
        raise NotImplementedError(
            'Matching must be implemented by a subclass.'
        )

    def _matching_score(self,
                        matching: Set[Tuple[Syscall, Syscall]],
                        g: nx.Graph,
                        s1_syscalls: List[Tuple[str, str, Syscall]],
                        s2_syscalls: List[Tuple[str, str, Syscall]],
                        all_traces: Set[Strace]) -> float:
        """Compute a score for a matching.

        Parameters
        ----------
        matching : Set[Tuple[Syscall, Syscall]]
            A matching in g.
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All other available traces.

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        raise NotImplementedError(
            'Matching must be implemented by a subclass.'
        )


class MaximumCardinalityMatching(MaximumMatching):
    """A comparison method based on maximum cardinality matching."""

    def _matching(self,
                  g: nx.Graph,
                  s1_syscalls: List[Tuple[str, str, Syscall]],
                  s2_syscalls: List[Tuple[str, str, Syscall]],
                  all_traces: Set[Strace]
                  ) -> Set[Tuple[Syscall, Syscall]]:
        """Compute a matching in g.

        Implementations of this method are expected to use the graph g to
        generate a matching, although may make modifications based on
        either syscall or other traces if necessary.

        Parameters
        ----------
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All other available traces.

        Returns
        -------
        Set[Tuple[Syscall, Syscall]]
            Set of matched syscall pairs.
        """
        # Get all syscalls from s1 that made it into the graph. This is one
        # of the two partites.
        partite1 = set(g.nodes) & set(s1_syscalls)

        # Compute matching
        return nx.algorithms.matching.matching_dict_to_set(
            nx.bipartite.maximum_matching(g, partite1)
        )

    def _matching_score(self,
                        matching: Set[Tuple[Syscall, Syscall]],
                        g: nx.Graph,
                        s1_syscalls: List[Tuple[str, str, Syscall]],
                        s2_syscalls: List[Tuple[str, str, Syscall]],
                        all_traces: Set[Strace]) -> float:
        """Compute a score for a matching.

        Parameters
        ----------
        matching : Set[Tuple[Syscall, Syscall]]
            A matching in g.
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All other available traces.

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        min_len = min(len(s1_syscalls), len(s2_syscalls))
        return len(matching) / min_len


class TFIDFMaximumWeightedMatching(MaximumMatching):

    def __init__(self, *args,
                 maxcardinality: bool = True,
                 tfidf_syscall_equality: Optional[SyscallEquality] = None,
                 **kwargs):
        """Initialize a new scoring method.

        Parameters
        ----------
        maxcardinality : bool
            If the maximum weighted matching should also have maximum
            cardinality.
        tfidf_syscall_equality : Optional[SyscallEquality]
            Equality method for computing TF-IDF. If not specified
            `self.syscall_equality`.
        """
        super().__init__(*args, **kwargs)
        self.maxcardinality = maxcardinality
        if tfidf_syscall_equality is None:
            self.tfidf_syscall_equality = self.syscall_equality
        else:
            self.tfidf_syscall_equality = tfidf_syscall_equality

    def _matching(self,
                  g: nx.Graph,
                  s1_syscalls: List[Tuple[str, str, Syscall]],
                  s2_syscalls: List[Tuple[str, str, Syscall]],
                  all_traces: Set[Strace]
                  ) -> Set[Tuple[Syscall, Syscall]]:
        """Compute a matching in g.

        Implementations of this method are expected to use the graph g to
        generate a matching, although may make modifications based on
        either syscall or other traces if necessary.

        Parameters
        ----------
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All available traces.

        Returns
        -------
        Set[Tuple[Syscall, Syscall]]
            Set of matched syscall pairs.
        """
        # Activate TF-IDF equality context
        with self.tfidf_syscall_equality():

            # Compute term frequencies for s1
            s1_frequencies = {}
            for _, _, syscall in s1_syscalls:
                if syscall not in s1_frequencies:
                    s1_frequencies[syscall] = 1
                else:
                    s1_frequencies[syscall] += 1

            # Normalize
            s1_max_frequency = max(s1_frequencies.values())
            for syscall in s1_frequencies:
                s1_frequencies[syscall] /= s1_max_frequency

            # Compute term frequencies for s2
            s2_frequencies = {}
            for _, _, syscall in s2_syscalls:
                if syscall not in s2_frequencies:
                    s2_frequencies[syscall] = 1
                else:
                    s2_frequencies[syscall] += 1

            # Normalize
            s2_max_frequency = max(s2_frequencies.values())
            for syscall in s2_frequencies:
                s2_frequencies[syscall] /= s2_max_frequency

            # Compute document frequency.
            document_frequencies = {}
            for s in set(map(lambda v: v[2], g.nodes)):

                if s not in document_frequencies:
                    document_frequencies[s] = 0

                for strace in all_traces:
                    if s in strace.trace_lines:
                        document_frequencies[s] += 1

            # Weight all edges
            num_documents = len(list(all_traces))
            for u, v, d in g.edges(data=True):

                # Unpack and potentially swap
                _, _, s1 = u
                _, _, s2 = v
                if v[0] == 's1':
                    s1, s2 = s2, s1

                # Compute tf-idf weighting. We use sx_frequencies[sy] to query
                # how important a syscall is to the trace it is being matched
                # in.
                s1_tfidf = (
                    s2_frequencies.get(s1, 0)
                    * math.log(num_documents / document_frequencies[s1])
                )
                s2_tfidf = (
                    s1_frequencies.get(s2, 0)
                    * math.log(num_documents / document_frequencies[s2])
                )
                d['weight'] = s1_tfidf * s2_tfidf

        return nx.max_weight_matching(g, maxcardinality=self.maxcardinality)

    def _matching_score(self,
                        matching: Set[Tuple[Syscall, Syscall]],
                        g: nx.Graph,
                        s1_syscalls: List[Tuple[str, str, Syscall]],
                        s2_syscalls: List[Tuple[str, str, Syscall]],
                        all_traces: Set[Strace]) -> float:
        """Compute a score for a matching.

        Parameters
        ----------
        matching : Set[Tuple[Syscall, Syscall]]
            A matching in g.
        g : nx.Graph
            Graph the matching should be computed for.
        s1_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the first strace.
        s2_syscalls : List[Tuple[str, str, Syscall]]
            All syscalls from the second strace.
        all_traces : Set[Strace]
            All other available traces.

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        # Minimum number of syscalls
        min_len = min(len(s1_syscalls), len(s2_syscalls))

        # Get matching weight
        weight = sum(g.edges[s1, s2]['weight'] for s1, s2 in matching)

        # Return weight normalized by number of syscalls
        return weight / min_len


class NormalizedInformationContent(ScoringMethod):
    """Scoring method using information content.

    The final similarity score for two straces is the sum of information
    content for each matching syscall found in both traces. Syscall information
    content is computed using the standard definition where P is the
    probability of finding that syscall in any given strace (from all_traces).

    https://en.wikipedia.org/wiki/Information_content
    http://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf

    Normalization is performed by transforming each syscall's information
    content to be in the range 0..1.
    """

    def __init__(self, *args, **kwargs):
        """Init."""
        super().__init__(*args, **kwargs)
        self._all_traces = None
        self._syscall_information_content = None

    def _information_content(self,
                             all_traces: Set[Strace]) -> Dict[Syscall, float]:
        """Compute and cache normalized information content."""
        if (self._all_traces is not all_traces
                or self._syscall_information_content is None):
            logger.info('Computing document frequencies.')

            # Cache traces
            self._all_traces = all_traces

            # Count how many traces each syscall appears in
            counter = Counter(chain.from_iterable(map(
                lambda s: set(s.trace_lines),
                all_traces
            )))
            total = len(all_traces)

            # Compute normalized information content
            #
            # The standard definition of information content is
            # -log(P) = -log(count / total).
            #
            # We normalize to the range 0..1 by dividing by the max value,
            # which is -log(1 / total). The negatives cancel, and dividing by
            # the log is equivalent to performing a log change of base to
            # base = (1 / total).
            base = 1 / total
            self._syscall_information_content = {
                k: math.log(v / total, base)
                for k, v in counter.items()
            }

        return self._syscall_information_content

    def _score(self, s1: Strace, s2: Strace, all_traces: Set[Strace]) -> float:
        """Compute a comparison score for two straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        # Compute information content with all executable parameters equal
        with ExecutableParameter.compare_equal():
            syscall_weights = self._information_content(all_traces)

        # Count syscall occurrences in compared traces
        s1_counts = Counter(s1.trace_lines)
        s2_counts = Counter(s2.trace_lines)

        # Get all syscalls shared by s1 and s2
        common_syscalls = set(s1_counts.keys()) & set(s2_counts.keys())

        # Get the minimum count from s1 or s2 of each common syscall
        min_counts = {
            syscall: min(s1_counts[syscall], s2_counts[syscall])
            for syscall in common_syscalls
        }

        # Compute score
        with ExecutableParameter.compare_equal():
            with logger.debug_straces_context():
                syscall_scores = sorted(
                    (
                        (
                            count,
                            syscall_weights[syscall] + 0,
                            count * syscall_weights[syscall] + 0,
                            syscall
                        )
                        for syscall, count in min_counts.items()
                    ),
                    key=lambda v: v[2],
                    reverse=True
                )
                logger.debug(
                    f'Found {sum(min_counts.values())} common syscalls.\n'
                    f'Common syscall definitions: \n'
                    f'count, weight,  score, syscall\n'
                    +  # Because implicit string concatenation > .join().
                    f'\n'.join(
                        f'{c:5d}, {w:1.4f}, {s:1.4f}, {syscall}'
                        for c, w, s, syscall in syscall_scores
                    )
                )
            score = sum(
                count * syscall_weights[s]
                for s, count in min_counts.items()
            )
            # TODO
            # score /= min(len(s1.trace_lines), len(s2.trace_lines))
            score *= 2 / (len(s1.trace_lines) + len(s2.trace_lines))

        return score


class JaccardCoefficient(ScoringMethod):
    """Scoring method using the Jaccard coefficient."""

    def _score(self,
               s1: Strace,
               s2: Strace,
               all_traces: Set[Strace]) -> float:
        """Compute a comparison score for two straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        # Get sets of tracelines for each strace
        s1_set = set(s1.trace_lines)
        s2_set = set(s2.trace_lines)

        # Compute intersection and union
        intersection = s1_set & s2_set
        union = s1_set | s2_set

        # Return jaccard coefficient (intersection / union)
        return len(intersection) / len(union)


class TFIDF(ScoringMethod):
    """Scoring method using TF-IDF.

    Syscalls from one strace are used as query terms for the other. The
    resulting TF-IDF score is normalized by the number of syscalls.
    """

    def _score(self,
               s1: Strace,
               s2: Strace,
               all_traces: Set[Strace]) -> float:
        """Compute a comparison score for two straces.

        Parameters
        ----------
        s1 : Strace
            First strace to be preprocessed.
        s2 : Strace
            Second strace to be preprocessed.
        all_traces : Set[Strace]
            All available traces. Preprocessing may use information from the
            global traces

        Returns
        -------
        float
            Comparison score in the range 0..1.
        """
        # Compare and potentially swap so that s1 is the smallest
        if len(s1.trace_lines) > len(s2.trace_lines):
            s1, s2 = s2, s1

        # Compute s2_frequencies
        s2_frequencies = {}
        for s in s2.trace_lines:
            if s not in s2_frequencies:
                s2_frequencies[s] = 1
            else:
                s2_frequencies[s] += 1

        # Normalize
        s2_max_frequency = max(s2_frequencies.values())
        for syscall in s2_frequencies:
            s2_frequencies[syscall] /= s2_max_frequency

        # Get a set of s1 syscalls
        s1_set = set(s1.trace_lines)

        # Compute document frequencies. We only need to look for syscalls that
        # appear in s1, because only the s1 query terms are involved in
        # computing tf-idf.
        document_frequencies = {}
        for s in s1_set:
            document_frequencies[s] = 0
            for strace in all_traces:
                if s in strace.trace_lines:
                    document_frequencies[s] += 1

        # Compute tfidf using s1 syscalls as the query terms
        s1_tfidf = sum(
            s2_frequencies.get(s, 0)
            * math.log(len(all_traces) / document_frequencies[s])
            for s in s1_set
        )

        # Normalize by the size of s1 and return
        return s1_tfidf / len(s1_set)
