"""Similarity metrics for syscalls."""


# Imports
from contextlib import contextmanager
from typing import Any, Generator

from lib.strace.classes import Syscall
from lib.strace.comparison import canonical_form


class SyscallEquality:
    """Base syscall equality class.

    Instances of this class are callable context managers. When operating in
    the syscall equality context, the Syscall class __eq__ and __hash__ methods
    are monkey patched with this class' equality comparison.

    Equality as implemented by subclasses must exhibit the substitution,
    reflexive, symmetric, and transitive properties of equality.
    """

    @contextmanager
    def __call__(self) -> Generator[None, None, None]:
        """Enable syscall equality.

        This method creates a context in which the Syscall class has been
        monkey patched with this objects equality and hashing functions.
        """
        # Save the initial functions so we can restore them later
        old_eq = Syscall.__eq__
        old_hash = Syscall.__hash__

        # Patch. Use the function reference from class because we don't want
        # to get the bound method.
        Syscall.__eq__ = self.__class__._equals
        Syscall.__hash__ = self.__class__._hash

        # Yield and then restore original functions on cleanup
        try:
            yield
        finally:
            Syscall.__eq__ = old_eq
            Syscall.__hash__ = old_hash

    def _equals(self: Syscall, other: Any) -> bool:
        """Determine equality between self and another object.

        Parameters
        ----------
        other : Any
            Object to compare with.

        Returns
        -------
        bool
            True if other is an equivalent syscall.
        """
        raise NotImplementedError()

    def _hash(self: Syscall) -> int:
        """Hash a syscall.

        Returns
        -------
        int
            Syscall hash.
        """
        raise NotImplementedError()


class NameEquality(SyscallEquality):
    """Syscall equality based on names."""

    def _equals(self: Syscall, other: Any) -> bool:
        """Determine name equality between self and another object.

        Parameters
        ----------
        other : Any
            Object to compare with.

        Returns
        -------
        bool
            True if other is an equivalent syscall.
        """
        if not isinstance(other, Syscall):
            return NotImplemented
        return self.name == other.name

    def _hash(self: Syscall) -> int:
        """Hash a syscall for name equality.

        Returns
        -------
        int
            Syscall hash.
        """
        return hash(self.name)


class StrictEquality(SyscallEquality):
    """Full syscall equality."""

    def _equals(self: Syscall, other: Any) -> bool:
        """Determine strict equality between self and another object.

        Parameters
        ----------
        other : Any
            Object to compare with.

        Returns
        -------
        bool
            True if other is an equivalent syscall.
        """
        return self.strict_equals(other)

    def _hash(self: Syscall) -> int:
        """Hash a syscall for strict equality.

        Returns
        -------
        int
            Syscall hash.
        """
        return self.strict_equals_hash()


class CanonicalEquality(SyscallEquality):
    """Syscall equality based on canonical forms.

    This class compares syscalls for equality by first converting them to
    some canonical form. This conversion may be based on automated techniques
    or domain knowledge about syscalls.
    """

    def _equals(self: Syscall, other: Any) -> bool:
        """Determine strict equality between self and another object.

        Parameters
        ----------
        other : Any
            Object to compare with.

        Returns
        -------
        bool
            True if other is an equivalent syscall.
        """
        if not isinstance(other, Syscall):
            return NotImplemented

        c_self = canonical_form.canonicalize(self)
        c_other = canonical_form.canonicalize(other)
        return c_self == c_other

    def _hash(self: Syscall) -> int:
        """Hash a syscall for strict equality.

        Returns
        -------
        int
            Syscall hash.
        """
        return hash(canonical_form.canonicalize(self))
