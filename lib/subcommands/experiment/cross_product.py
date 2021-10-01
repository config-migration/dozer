"""Cross-product experiment CLI."""


# Imports
from argparse import Namespace
from typing import Any, Tuple, Union

from lib.experiments import cross_product


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


def run(argv: Namespace):
    """Run cross-product experiment.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Run experiment
    df, mappings = cross_product.run(collector=argv.collector)

    # Print result dataframe
    print(f'Raw Results: \n{df}\n')
    print(f'Column Normalized Results:\n{df.divide(df.max(axis=0), axis=1)}\n')
    print(f'Row Normalized Results:\n{df.divide(df.max(axis=1), axis=0)}\n')

    # Print mappings
    for s1, s2, mapping in mappings:
        mapping_str = '\n'.join(
            f'{_get(s1.arguments, v1)} <=> {_get(s2.arguments, v2)}'
            for v1, v2 in mapping
        )
        print(
            f'Mapping for:\n'
            f'    ({s1.executable}, {s1.arguments}) =>\n'
            f'    ({s2.executable}, {s2.arguments})\n'
            f'\n'
            f'    {mapping_str}\n'
        )
