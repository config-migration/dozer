"""Dockerfile Top 100 experiment CLI."""


# Imports
from argparse import Namespace
from ast import literal_eval
from pathlib import Path
from typing import Any, Tuple, Union
import csv
import shutil

import pandas

from lib import logger
from lib.experiments import EXPERIMENTS
from lib.experiments.dockerfile_top_100 import run as experiment
from lib.strace.classes import Strace
from lib.strace.comparison.scoring import ScoringResult


# Constants
DEFAULT_REPORT_TOP_N_MATCHES = 5


# Paths
DEFAULT_OUTPUT_DIR: Path = EXPERIMENTS / 'dockerfile_top_100'


def _get(arguments: Union[list, dict],
         key: Tuple[Union[int, str], ...]) -> Any:
    """Get argument value by key.

    Parameters
    ----------
    arguments : Union[list, dict]
        Executable arguments.
    key : Tuple[Union[int, str], ...]
        Argument key

    Returns
    -------
    Any
        Argument value
    """
    for k in key:
        arguments = arguments[k]
    return arguments


def _run(baseline: bool, output_dir: Path, server: int, of: int,
         report_top_n_matches: int):
    """Run experiment and print results.

    Parameters
    ----------
    baseline : bool
        Whether or not to run the baseline experiment.
    output_dir : Path
        Output directory for results.
    server : int
        Server number.
    of : int
        Total number of servers.
    report_top_n_matches : int
        Number of matches to print to stdout.
    """
    # Run experiment.
    results = experiment.run(server=server, of=of, baseline=baseline)

    # Recreate output directory
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    # Process and display results for all traces.
    for trace, comparison_results in results:

        # Generate output file path
        output_file = (
            output_dir / f'{trace.executable}_{trace.arguments_hash.hex()}.csv'
        )

        # Open output file for writing
        with open(output_file, 'w') as output_file_fd:

            # Write results in order
            writer = csv.writer(output_file_fd)
            writer.writerow((
                'score',
                'normalized_score',
                'system',
                'executable',
                'arguments_hash',
                'arguments',
                'mapped_keys',
                'mapped_values'
            ))
            writer.writerow((
                None,
                None,
                trace.system,
                trace.executable,
                trace.arguments_hash.hex(),
                trace.arguments,
                None,
                None,
            ))
            for comparison_result in comparison_results:
                ansible_trace = comparison_result.s2
                mapped_values = [
                    (
                        _get(trace.arguments, k1),
                        _get(ansible_trace.arguments, k2)
                    )
                    for k1, k2 in comparison_result.mapping
                ]

                writer.writerow((
                    comparison_result.score,
                    comparison_result.normalized_score,
                    ansible_trace.system,
                    ansible_trace.executable,
                    ansible_trace.arguments_hash.hex(),
                    ansible_trace.arguments,
                    comparison_result.mapping,
                    mapped_values,
                ))

        # Print top n comparison results.
        top_n_comparison_results = comparison_results[:report_top_n_matches]
        print(f'Dockerfile Executable: {trace.executable}, {trace.arguments}')
        print()

        for idx, comparison_result in enumerate(top_n_comparison_results):

            ansible_trace = comparison_result.s2

            print(
                f'    {idx}. {ansible_trace.executable} '
                f'{ansible_trace.arguments}'
            )

            if comparison_result.mapping:
                mapping_str = '       \n'.join(
                    f'{_get(trace.arguments, v1)} <=> '
                    f'{_get(ansible_trace.arguments, v2)}'
                    for v1, v2 in comparison_result.mapping
                )
                print(f'       {mapping_str}')

        print()


def _postprocess(output_dir: Path):
    """Run experiment postprocessing.

    Parameters
    ----------
    output_dir : Path
        Experiment output directory.
    """
    if not output_dir.exists():
        raise ValueError(
            f'The output directory `{output_dir}` does not exist.'
        )

    logger.info('Loading experiment results.')
    all_results = []
    for result_file in list(sorted(output_dir.glob('*.csv'))):

        # Skip any prior postprocessing output.
        if result_file.name == 'postprocessing.csv':
            continue

        # Load and eval arguments.
        logger.info(f'Loading from file `{result_file}`.')
        df = pandas.read_csv(result_file)
        df['arguments'] = df['arguments'].map(literal_eval)

        # Get the first row as the linux executable.
        linux_row = df.iloc[0]
        df = df.drop([0])
        df['mapped_keys'] = df['mapped_keys'].map(literal_eval)

        # Format the linux strace.
        linux_strace = Strace(
            system=linux_row.system,
            executable=linux_row.executable,
            arguments=linux_row.arguments,
            trace_lines=[],
        )

        # Get results for the linux strace.
        results = []
        for _, ansible_row in df.iterrows():
            ansible_strace = Strace(
                system=ansible_row.system,
                executable=ansible_row.executable,
                arguments=ansible_row.arguments,
                trace_lines=[]
            )
            results.append(ScoringResult(
                score=ansible_row.score,
                normalized_score=ansible_row.normalized_score,
                s1=linux_strace,
                s2=ansible_strace,
                mapping=ansible_row.mapped_keys
            ))

        # Append to all results.
        results = list(sorted(results, reverse=True))
        all_results.append((linux_strace, results))

    # Postprocess all results.
    postprocess_results = experiment.postprocess(all_results)

    # Write results to csv file.
    df = pandas.DataFrame(
        [
            [
                validation.score,
                result.source.system,
                result.source.executable,
                result.source.arguments_hash.hex(),
                result.source.arguments,
                result.target.system,
                result.target.executable,
                result.target.arguments_hash.hex(),
                result.target.arguments,
                result.migration.system,
                result.migration.executable,
                result.migration.arguments,
                result.mapping,
            ]
            for result, validation in postprocess_results
        ],
        columns=[
            'score',
            'source_system',
            'source_executable',
            'source_arguments_hash',
            'source_arguments',
            'target_system',
            'target_executable',
            'target_arguments_hash',
            'target_arguments',
            'migration_system',
            'migration_executable',
            'migration_arguments',
            'mapped_keys',
        ]
    )
    df.to_csv(output_dir / 'postprocessing.csv', index=False)

    # Print output in human readable format.
    print('Postprocessing Results')
    print()
    for migration_result, validation in postprocess_results:
        print(
            f'{migration_result.source.executable_repr}:\n'
            f'    Original Target: {migration_result.target.executable_repr}\n'
            f'    Mapping:         {migration_result.mapping}\n'
            f'    Migration:       '
            f'{migration_result.migration.executable_repr}\n'
            f'    Score:           {validation.score}\n'
        )


def run(argv: Namespace):
    """Run Dockerfile Top 100 experiment.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Get parameters.
    postprocess = argv.postprocess
    baseline = argv.baseline
    output_dir = argv.output_dir.absolute()
    server = argv.server
    of = argv.of
    report_top_n_matches = argv.report_top_n_matches

    if postprocess:
        _postprocess(output_dir=output_dir)
    else:
        _run(
            baseline=baseline,
            output_dir=output_dir,
            server=server,
            of=of,
            report_top_n_matches=report_top_n_matches
        )
