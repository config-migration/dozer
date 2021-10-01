"""Compare straces."""


# Imports.
from argparse import Namespace
from typing import Any, Tuple, Union

from sqlalchemy.sql import and_, ColumnElement

from lib.strace import comparison
from lib.strace.comparison import preprocessing
from lib.strace.tables import (
    executables as t_executables,
    straces as t_straces
)


# Constants
DEFAULT_TOP_N = 5


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


def _parse_where_part(part: str) -> ColumnElement:
    """Parse a string into a where condition.

    Currently only equality is supported.

    Parameters
    ----------
    part : str
        ``attribute = value`` string.

    Returns
    -------
    ColumnElement
        A sqlalchemy where condition matching

    Raises
    ------
    ValueError
        Raised when an unsupported attribute is passed.
    """
    if '=' not in part:
        raise ValueError('Condition does not contain a value.')

    attribute, value = map(str.strip, part.split('='))

    if attribute in ('system', 'executable'):
        return getattr(t_executables.c, attribute) == value
    elif attribute == 'arguments_hash':
        return getattr(t_executables.c, attribute) == bytes.fromhex(value)
    elif attribute in ('id', 'collector', 'collector_assigned_id'):
        return getattr(t_straces.c, attribute) == value
    else:
        raise ValueError('Unsupported attribute.')


def _parse_where(where: str) -> ColumnElement:
    """Parse a where clause.

    Parameters
    ----------
    where : str
        Where clause.

    Returns
    -------
    ColumnElement
        A sqlalchemy where condition.

    Raises
    ------
    ValueError
        Raised when an unsupported condition is provided.
    """
    return and_(*map(_parse_where_part, where.split(',')))


def run(argv: Namespace):
    """Run comparison.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Process arguments
    kwargs = {}

    s1 = _parse_where(argv.s1)
    s2 = _parse_where(argv.s2)

    if argv.load:
        if argv.load.casefold() == 'true':
            kwargs['load'] = True
        elif argv.load.casefold() == 'false':
            kwargs['load'] = False
        else:
            kwargs['load'] = _parse_where(argv.load)

    if (argv.by
            and argv.by.startswith('compare')
            and hasattr(comparison, argv.by)):
        kwargs['by'] = getattr(comparison, argv.by)

    if argv.global_preprocessors:
        kwargs['global_preprocessors'] = [
            getattr(preprocessing, preprocessor)
            for preprocessor in argv.global_preprocessors.split(',')
        ]

    # Run comparison
    results = comparison.load_and_compare(
        s1=s1,
        s2=s2,
        **kwargs
    )

    # Print results
    num_top_n = argv.top_n
    for s1_results in results:

        top_n = sorted(s1_results, reverse=True)[:num_top_n]

        for idx, result in enumerate(top_n):

            s1_trace = result.s1
            s2_trace = result.s2

            print(
                f'S1 Executable: {s1_trace.executable}, {s1_trace.arguments}\n'
            )
            print(
                f'    {idx}. Executable: {s2_trace.executable} '
                f'{s2_trace.arguments}\n'
                f'       Score:      {result.score}'
            )

            if result.mapping:
                mapping_str = '                   \n'.join(
                    f'{_get(s1_trace.arguments, v1)} <=> '
                    f'{_get(s2_trace.arguments, v2)}'
                    for v1, v2 in result.mapping
                )
                print(f'       Mapping:    {mapping_str}')

        print()
