"""Other strace utilities."""


# Imports
from typing import Any


def hashable_arguments_representation(a: Any) -> Any:
    """Return a hashable representation of an object.

    This is mostly meant to support JSON objects and arrays (dicts and lists
    containing other dicts and lists or primitives).

    Parameters
    ----------
    a : Any
        Any object.

    Returns
    -------
    Any
        A hashable object.
    """
    # Convert lists to tuples of hashable objects.
    if isinstance(a, list):
        return tuple(map(hashable_arguments_representation, a))

    # Convert dicts to tuples of (key, hashable) pairs. Keys are guaranteed
    # to be hashable.
    if isinstance(a, dict):
        return tuple(
            (k, hashable_arguments_representation(v))
            for k, v in sorted(
                ((repr(k), v) for k, v in a.items())
            )
        )

    # Try to return a string representation of a. Strings are always hashable
    # and support ordering, etc.
    try:
        return repr(a)
    except TypeError:
        raise Exception(
            f'Cannot create a hashable representation of type {type(a)}'
        )
