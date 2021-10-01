"""Shell utilities."""


# Imports.
from typing import List


# Special characters.
SHELL_SPECIAL_CHARS = set('();<>|& ')


def join(cmd_list: List[str]) -> str:
    """Join an command list into a command string.

    Parameters
    ----------
    cmd_list : List[str]
        List of command parts.

    Returns
    -------
    str
        Full command string.
    """
    return ' '.join(map(quote, cmd_list))


def quote(part: str) -> str:
    """Quote a shell command part.

    This implementation is provided as an alternative to ``shlex.quote``,
    because the library implementation improperly quotes parts like ``>>`` and
    `/*.sh`, which we need to be unquoted when passing commands to Docker or
    other scripts.

    The implementation is as follows:

    - If the part is an empty string, it is returned as ``''``.
    - Else, if the part is entirely composed of special characters, which may
      be syntax such as shell redirection (``>>``, etc.), then it is returned
      as is.
    - Else, if the part contains any special symbols, it is returned quoted.
      Quoting is performed by escaping any single quotes with ``'\''`, then
      wrapping the part in single quotes.
    - Else, the part is returned as is.

    Parameters
    ----------
    part : str
        Command part.

    Returns
    -------
    str
        Quoted command part.
    """
    if not part:
        return ''
    elif len(set(part)) == 1 and part[0] in SHELL_SPECIAL_CHARS:
        return part
    elif any(char in part for char in SHELL_SPECIAL_CHARS):
        return "'" + part.replace("'", "'\\''") + "'"
    else:
        return part
