"""Docker based validation."""


# Imports.
from argparse import Namespace
from dataclasses import dataclass
from shlex import shlex
from typing import Union
import json

from sqlalchemy.sql import and_, cast, or_, select, ColumnElement
from sqlalchemy.types import JSON

from lib.strace.tables import executables as t_executables
from lib.validation.docker import validate_pairs


@dataclass
class Exe:
    """Minimal executable representation."""

    system: str
    executable: str
    arguments: Union[dict, list]


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

    if attribute in ('id', 'system', 'executable'):
        return getattr(t_executables.c, attribute) == value
    elif attribute == 'arguments_hash':
        return t_executables.c.arguments_hash == bytes.fromhex(value)
    elif attribute == 'arguments':
        return t_executables.c.arguments == cast(value, JSON)
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
    """Run validation.

    Parameters
    ----------
    argv : Namespace
        Namespace object from argparse. This must have all required arguments
        and parameters as configured by the CLI entrypoint.
    """
    # Load executables.
    executables = []
    if argv.executable:
        executables += (
            Exe(
                system=exe.system,
                executable=exe.executable,
                arguments=exe.arguments
            )
            for exe in (
                select([
                    t_executables.c.system,
                    t_executables.c.executable,
                    t_executables.c.arguments,
                ])
                .where(or_(*map(_parse_where, argv.executable)))
                .execute()
            )
        )
    if argv.linux:
        for exe in argv.linux:
            lexer = shlex(exe, punctuation_chars=True, posix=True)
            lexer.whitespace_split = True
            executable, *args = lexer
            executables.append(Exe(
                system='linux',
                executable=executable,
                arguments=args,
            ))
    if argv.ansible:
        for exe in argv.ansible:
            executable, args = exe.split(maxsplit=1)
            args = json.loads(args)
            executables.append(Exe(
                system='ansible',
                executable=executable,
                arguments=args,
            ))
    if argv.setup:
        setup = '\n'.join(argv.setup)
    else:
        setup = None

    # Validate
    results = validate_pairs(executables, setup=setup)
    for result in results:
        print(result)
