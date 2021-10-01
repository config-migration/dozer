"""Utilities to search for appropriate migrations."""


# Imports
from __future__ import annotations
from abc import ABC, abstractmethod
from collections import OrderedDict
from copy import copy
from pprint import pformat
from typing import (
    Any, Dict, Generator, List, Optional, Set, Sequence, Tuple, Union,
)

from lib import logger
from lib.strace.classes import (
    ExecutableParameter, MigrationResult, ParameterMapping, Strace
)
from lib.strace.comparison import ScoringResult
from lib.strace.util import hashable_arguments_representation
from lib.validation.docker import (
    validation_generator, Validatable, ValidationResult
)


# Constants
DEFAULT_NUM_EXECUTABLES = 20
DEFAULT_NUM_DEFINITIONS = 10


class MappingTree(ABC):
    """Tree that contains information about parameter mappings."""

    @classmethod
    def from_value(cls, value: Any) -> MappingTree:
        """Create a mapping tree from some value.

        Parameters
        ----------
        value : Any
            Any value. This is typically the arguments to some executable.

        Returns
        -------
        MappingTree
            A mapping tree initialized from ``value``.
        """
        if isinstance(value, MappingTree):
            return value
        elif isinstance(value, list):
            return ListNode([
                MappingTree.from_value(child)
                for child in value
            ])
        elif isinstance(value, dict):
            return DictNode({
                key: MappingTree.from_value(child)
                for key, child in value.items()
            })
        else:
            return ValueNode(value)

    def __str__(self) -> str:
        """Represent self as a human readable string.

        Returns
        -------
        str
            A pretty formatted string of the tree value.
        """
        return pformat(self.to_value())

    def __repr__(self) -> str:
        """Represent self as a repr string.

        Returns
        -------
        str
            The repr string of the tree value.
        """
        return repr(self.to_value())

    @abstractmethod
    def get_mapped_keys(self) -> Set[Tuple[str, ...]]:
        """Get all mapped keys belonging to a node or its children.

        Parameters
        ----------
        Set[Tuple[str, ...]]
            All keys for values mapped to this node or its children.
        """
        raise NotImplementedError('not implemented')

    @abstractmethod
    def get_mapping(self) -> ParameterMapping:
        """Get a parameter mapping.

        Returns
        -------
        ParameterMapping
            A parameter mapping from all contained nodes.
        """
        raise NotImplementedError('not implemented')

    @abstractmethod
    def to_value(self) -> Any:
        """Convert the tree to a regular Python value.

        For container nodes, this will be the appropriate container type with
        elements created from child ``to_value`` results. For value nodes, this
        is the node value.

        Returns
        -------
        Any
            Python value.
        """
        raise NotImplementedError('not implemented')


class ContainerNode(MappingTree, ABC):
    """A mapping tree containing children.

    Container nodes are either empty or inner nodes.
    """

    def __init__(self, children: Union[
                 Dict[Any, MappingTree], List[MappingTree]]):
        """Create a new container node.

        Parameters
        ----------
        children : Union[Dict[Any, MappingTree], List[MappingTree]]
            Child nodes.
        """
        super().__init__()
        self.children = children

    def __getitem__(self, key: Any) -> MappingTree:
        """Get a child node by key.

        Parameters
        ----------
        key : Any
            Child key. This must be a valid key for ``self.children``.

        Returns
        -------
        MappingTree
            Child found by ``key``.
        """
        return self.children[key]

    def __setitem__(self, key: Any, value: MappingTree):
        """Set a child node by key.

        Parameters
        ----------
        key : Any
            Child key. This must be a valid key for ``self.children``.
        value : MappingTree
            Child found by ``key``.
        """
        self.children[key] = value

    def __delitem__(self, key: Any):
        """Delete a child node by key.

        Parameters
        ----------
        key : Any
            Child key. This must be a valid key for ``self.children``.
        """
        del self.children[key]

    @abstractmethod
    def insert_after(self, after: Any, key: Any, node: MappingTree):
        """Insert a new node directly after another.

        Parameters
        ----------
        after : Any
            Key for the node to insert after.
        key : Any
            Key for the new node.
        node : MappingTree
            Node to insert.
        """
        raise NotImplementedError('not implemented')

    @abstractmethod
    def keys(self) -> List[Any]:
        """Get keys for all children.

        Returns
        -------
        List[Any]
            All keys for ``self.children``.
        """
        raise NotImplementedError('not implemented')


class ListNode(ContainerNode):
    """A container node where the container is a list."""

    def to_value(self) -> list:
        """Convert the tree to a regular Python list.

        Returns
        -------
        list
            Python list.
        """
        return [child.to_value() for child in self.children]

    def insert_after(self, after: Any, key: Any, node: MappingTree):
        """Insert a new node directly after another.

        Parameters
        ----------
        after : Any
            Key for the node to insert after.
        key : Any
            Key for the new node. Ignored by list nodes. The new key will be
            determined by the index (``after + 1``).
        node : MappingTree
            Node to insert.
        """
        if after is None:
            after = -1
        self.children.insert(after + 1, node)

    def keys(self) -> List[int]:
        """Get keys for all children.

        Returns
        -------
        List[int]
            All keys for ``self.children``.
        """
        return list(range(len(self.children)))

    def get_mapped_keys(self) -> Set[Tuple[str, ...]]:
        """Get all mapped keys belonging to a node or its children.

        Parameters
        ----------
        Set[Tuple[str, ...]]
            All keys for values mapped to this node or its children.
        """
        return {
            key
            for child in self.children
            for key in child.get_mapped_keys()
        }

    def get_mapping(self) -> ParameterMapping:
        """Get a parameter mapping.

        Returns
        -------
        ParameterMapping
            A parameter mapping from all contained nodes.
        """
        return [
            (src, (str(idx), *dest))
            for idx, child in enumerate(self.children)
            for src, dest in child.get_mapping()
        ]


class DictNode(ContainerNode):
    """A container node where the container is a dict."""

    def __init__(self, *args, **kwargs):
        """Create a new dict node."""
        super().__init__(*args, **kwargs)
        self.children = OrderedDict(self.children)

    def to_value(self) -> dict:
        """Convert the tree to a regular Python dict.

        Returns
        -------
        dict
            Python dict.
        """
        return {
            key: child.to_value()
            for key, child in self.children.items()
        }

    def insert_after(self, after: Any, key: Any, node: MappingTree):
        """Insert a new node directly after another.

        Parameters
        ----------
        after : Any
            Key for the node to insert after.
        key : Any
            Key for the new node.
        node : MappingTree
            Node to insert.
        """
        self.children[key] = node
        keys = list(reversed(self.keys()))
        if after is not None:
            while keys:
                k = keys.pop()
                if k == after:
                    break
        while keys:
            k = keys.pop()
            if k == key:
                break
            self.children.move_to_end(k)

    def keys(self) -> List[Any]:
        """Get keys for all children.

        Returns
        -------
        List[Any]
            All keys for ``self.children``.
        """
        return list(self.children.keys())

    def get_mapped_keys(self) -> Set[Tuple[str, ...]]:
        """Get all mapped keys belonging to a node or its children.

        Parameters
        ----------
        Set[Tuple[str, ...]]
            All keys for values mapped to this node or its children.
        """
        return {
            key
            for child in self.children.values()
            for key in child.get_mapped_keys()
        }

    def get_mapping(self) -> ParameterMapping:
        """Get a parameter mapping.

        Returns
        -------
        ParameterMapping
            A parameter mapping from all contained nodes.
        """
        return [
            (src, (key, *dest))
            for key, child in self.children.items()
            for src, dest in child.get_mapping()
        ]


class ValueNode(MappingTree):
    """A mapping tree containing a single value.

    Value nodes are always leaf nodes.
    """

    def __init__(self, value: Any):
        """Create a new value node.

        Parameters
        ----------
        value : Any
            Node value.
        """
        super().__init__()
        self.value = value

    def to_value(self) -> Any:
        """Convert the tree to a regular Python value.

        Returns
        -------
        Any
            Python value.
        """
        return self.value

    def get_mapped_keys(self) -> Set[Tuple[str, ...]]:
        """Get all mapped keys belonging to a node or its children.

        Parameters
        ----------
        Set[Tuple[str, ...]]
            All keys for values mapped to this node or its children.
        """
        return set()

    def get_mapping(self) -> ParameterMapping:
        """Get a parameter mapping.

        Returns
        -------
        ParameterMapping
            A parameter mapping from all contained nodes.
        """
        return []


class MappedValueNode(ValueNode):
    """A mapping tree with a value that has been mapped to another tree."""

    def __init__(self,
                 key: Tuple[str, ...],
                 value: Any,
                 original: Optional[MappingTree]):
        """Initialize a new mapped value node.

        Parameters
        ----------
        key : Tuple[str, ...]
            Identifier for the mapped value.
        value : Any
            The mapped value.
        original : Optional[MappingTree]
            The original node that the mapped value is mapped to.
        """
        super().__init__(value)
        self.key = key
        self.original = original

    def get_mapped_keys(self) -> Set[Tuple[str, ...]]:
        """Get all mapped keys belonging to a node or its children.

        Parameters
        ----------
        Set[Tuple[str, ...]]
            All keys for values mapped to this node or its children.
        """
        return {self.key}

    def get_mapping(self) -> ParameterMapping:
        """Get a parameter mapping.

        Returns
        -------
        ParameterMapping
            A parameter mapping from all contained nodes.
        """
        return [(self.key, ())]


class TreeWalkingException(Exception):
    """Exception encountered while walking a mapping tree."""


class TreeWalker:
    """A helper class for iterating over and mutating a mapping tree."""

    def __init__(self, root: ContainerNode, fall_off_lists: bool = False):
        """Create a new tree walker.

        This class is designed for iterating over trees for executable
        arguments. By design, the root node is not visitable, meaning that it
        cannot be modified. This guarantees the basic structure of arguments
        (dicts for Ansible, lists for Linux, etc.) remains unchanged.

        The walker begins pointing at the first child of ``root``.

        Usage:
        >>> tree = MappingTree.from_value({
        >>>     'key1': [
        >>>         [1, '2', [3, '4']],
        >>>         {
        >>>             1: ['val1'],
        >>>             2: ['val2']
        >>>         }
        >>>     ],
        >>>     'key2': [
        >>>         [],
        >>>         {}
        >>>     ]
        >>> })
        >>> walker = TreeWalker(tree, fall_off_lists=True)
        >>>
        >>> walker.next()
        >>> walker.down()
        >>> walker.down()
        >>> walker.next()
        >>> walker.replace(ValueNode('NEW NODE'))
        >>> print(tree)
        >>> # {'key1': [[1, '2', [3, '4']], {1: ['val1'], 2: ['val2']}],
        >>> #  'key2': [[None, 'NEW NODE'], {}]}

        Parameters
        ----------
        root : ContainerNode
            Root node. This must be a container node, and only children will
            be provided by iteration.
        fall_off_lists : bool
            Whether or not iteration can fall off the end of a list. If true,
            list indices > 0 can be visited and modified, even if they do not
            exist in the list node. Lists will be extended when needed.

        """
        self._root: ContainerNode = root
        self._ancestors: List[ContainerNode] = []
        self._ancestor_keys: List[Sequence[Any]] = []
        self._ancestor_current_key_idx: List[int] = []
        self._parent: ContainerNode = root
        self._parent_keys: List[str] = self._parent.keys()
        self._parent_current_key_idx: int = 0
        self._fall_off_lists = fall_off_lists
        self.sentinel = object()

    def __str__(self) -> str:
        """Represent self as a human readable string.

        Returns
        -------
        str
            The current node, as a string.
        """
        return str(self._current_node())

    def fall_off_lists(self, fall_off_lists: bool):
        """Change list iteration behavior.

        Parameters
        ----------
        fall_off_lists : bool
            Whether or not the walker can fall off the ends of lists.
        """
        self._fall_off_lists = fall_off_lists

    def map(self, key: Tuple[str, ...], value: Any):
        """Map the current node to a new value.

        Parameters
        ----------
        key : Tuple[str, ...]
            Mapped key. This should be an identifier for the mapped value.
        value : Any
            New value.
        """
        self.replace(MappedValueNode(key, value, self._current_node()))

    def unmap(self):
        """Unmap the current node.

        If the original value of the node is ``None``, the node will be
        removed. Unlike ``remove``, ``unmap`` remains pointing at the same
        location when this happens.
        """
        node = self._current_node()

        if not isinstance(node, MappedValueNode):
            return

        if node.original is not None:
            self.replace(node.original)
        else:
            self.remove()
            self.next()

    def replace(self, node: MappingTree) -> Optional[MappingTree]:
        """Replace the current node.

        If the walker has fallen off the end of a list node, it will extend
        the node's children up to the current position. New nodes are value
        nodes wrapping ``None`` except for the last one, which is ``node``.

        Parameters
        ----------
        node : MappingTree
            New node that will replace the current node.

        Returns
        -------
        Optional[MappingTree]
            The replaced node.
        """
        if (isinstance(self._parent, ListNode)
                and self._parent_current_key_idx >= len(self._parent_keys)):
            start = len(self._parent_keys)
            stop = self._parent_current_key_idx + 1
            self._parent_keys.extend(range(start, stop))
            self._parent.children.extend([ValueNode(None)] * (stop - start))
        old = self._current_node()
        self._parent[self._current_key()] = node
        return old

    def remove(self) -> Tuple[Any, Optional[MappingTree]]:
        """Remove the current node.

        After removal, the new current node will be the one prior to the
        removed node. This allows subsequent calls to ``next()`` to function
        as expected. If the removed node is the first node of a collection,
        removing it will cause the walker to point just before the start of
        the collection.

        Returns
        -------
        Any
            The key of the removed node. This will be ``None`` if the walker
            is not currently pointing at a node.
        """
        # If not pointing at a node.
        if self._current_node() is None:
            return None, None

        # Get the current key, delete the node, and return the key.
        key = self._current_key()
        node = self._current_node()
        del self._parent[key]
        self._parent_keys = self._parent.keys()
        self._parent_current_key_idx -= 1
        return key, node

    def insert_next(self, key: Any, node: MappingTree):
        """Insert a new node directly after the current one.

        After insertion, the current node will be the inserted node. Note that
        >>> key, node = walker.remove()
        >>> walker.insert_next(key, node)
        results in the original tree.

        Does nothing if ``node`` is None, making it safe to call remove/insert
        after the end of a list.

        Parameters
        ----------
        node : MappingTree
            Node to be inserted.
        key : Any
            Key for the node.
        """
        if node is None:
            return
        self._parent.insert_after(self._current_key(), key, node)
        self._parent_keys = self._parent.keys()
        self._parent_current_key_idx += 1

    def reset(self) -> Optional[MappingTree]:
        """Reset the walker to point to the first child of root.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        self.__init__(self._root, fall_off_lists=self._fall_off_lists)
        return self._current_node()

    def _current_key(self) -> Any:
        """Get the key pointing to the current node.

        If the walker has fallen off the end of a list, the key will be
        ``None``.

        Returns
        -------
        Any
            Key.
        """
        if 0 <= self._parent_current_key_idx < len(self._parent_keys):
            return self._parent_keys[self._parent_current_key_idx]
        return None

    def _current_node(self) -> Optional[MappingTree]:
        """Get the current node.

        Returns
        -------
        Optional[MappingTree]
            The current node. Will be ``None`` if the current key does not
            exist.
        """
        key = self._current_key()
        if key is not None:
            return self._parent[key]
        return None

    def can_move_up(self) -> bool:
        """Whether or not the walker can move up the tree.

        Returns
        -------
        bool
            True iff the walker can move up the tree.
        """
        return bool(self._ancestors)

    def up(self) -> Optional[MappingTree]:
        """Move up the tree.

        Raises
        ------
        TreeWalkingException
            Raised if the walker cannot move up the tree.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        if not self.can_move_up():
            raise TreeWalkingException('Cannot move up.')
        self._parent = self._ancestors.pop()
        self._parent_keys = self._ancestor_keys.pop()
        self._parent_current_key_idx = self._ancestor_current_key_idx.pop()
        return self._current_node()

    def can_move_down(self) -> bool:
        """Whether or not the walker can move into the current node.

        This is true if the current node is a non-empty container, or if it
        is an empty list and fall off lists is true.

        Returns
        -------
        bool
            True iff the walker can move down the tree.
        """
        node = self._current_node()
        return (
            (isinstance(node, ContainerNode) and node.keys())
            or (self._fall_off_lists and isinstance(node, ListNode))
        )

    def down(self) -> Optional[MappingTree]:
        """Move down into a container node.

        Raises
        ------
        TreeWalkingException
            Raised if the walker cannot move down the tree.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        if not self.can_move_down():
            raise TreeWalkingException('Cannot move down.')
        self._ancestors.append(self._parent)
        self._ancestor_keys.append(self._parent_keys)
        self._ancestor_current_key_idx.append(self._parent_current_key_idx)
        self._parent = self._current_node()
        self._parent_keys = self._parent.keys()
        self._parent_current_key_idx = 0
        return self._current_node()

    def down_to_key(self, key: Tuple[str, ...]) -> Optional[MappingTree]:
        """Move down to a specific key.

        Parameters
        ----------
        key : Tuple[str, ...]
            A sequence of keys for a nested element.

        Raises
        ------
        TreeWalkingException
            Raised if the walker cannot move to the specified key.

        Returns
        -------
        Optional[MappingTree]
            The node at the given key.
        """
        # Split the key into the first and remaining parts.
        first, *rest = key

        # Reset the walker so that we are guaranteed to start iteration from
        # the root.
        self.reset()

        # Walk to the first key in the current container.
        while (self._current_key() != first
               and self.can_move_next()
               and self._current_node() is not None):
            self.next()
        if self._current_key() != first:
            raise TreeWalkingException('Cannot move down to key.')

        # For each of the remaining parts, move down and then walk to the next
        # part of the key.
        for part in rest:
            self.down()
            while (self._current_key() != part
                   and self.can_move_next()
                   and self._current_node() is not None):
                self.next()
            if self._current_key() != part:
                raise TreeWalkingException('Cannot move down to key.')

        return self._current_node()

    def can_move_next(self) -> bool:
        """Whether or not the walker can move to the next sibling node.

        This is true if a next node exists, or if the walker is inside of a
        list and fall off lists is true.

        Returns
        -------
        bool
            True iff the walker can move to the next sibling node.
        """
        return (
            self._parent_current_key_idx < len(self._parent_keys) - 1
            or (self._fall_off_lists and isinstance(self._parent, ListNode))
        )

    def next(self) -> Optional[MappingTree]:
        """Move to the next sibling node.

        Raises
        ------
        TreeWalkingException
            Raised if the walker cannot move to the next node.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        if not self.can_move_next():
            raise TreeWalkingException('Cannot move next.')
        self._parent_current_key_idx += 1
        return self._current_node()

    def can_move_previous(self) -> bool:
        """Whether or not the walker can move to the previous sibling node.

        Returns
        -------
        bool
            True iff the walker can move to the previous sibling.
        """
        return self._parent_current_key_idx > 0

    def previous(self) -> Optional[MappingTree]:
        """Move to the previous sibling node.

        Raises
        ------
        TreeWalkingException
            Raised if the walker cannot move to the previous node.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        if not self.can_move_previous():
            raise TreeWalkingException('Cannot move previous.')
        self._parent_current_key_idx -= 1
        return self._current_node()

    def last(self) -> Optional[MappingTree]:
        """Move to the last sibling node.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        if len(self._parent_keys) == 0:
            self._parent_current_key_idx = 0
        else:
            self._parent_current_key_idx = len(self._parent_keys) - 1
        return self._current_node()

    def first(self) -> Optional[MappingTree]:
        """Move to the first sibling node.

        Returns
        -------
        Optional[MappingTree]
            The current node after moving.
        """
        self._parent_current_key_idx = 0
        return self._current_node()

    def postorder_traversal(self) -> Generator[MappingTree, None, None]:
        """Perform a postorder traversal from root.

        Returns
        -------
        Generator[MappingTree, None, None]
            Generator that yields nodes as a postorder traversal of the tree.
            The yielded node can be modified, or replaced by calling
            ``replace``.
        """
        # Reset to to guarantee we start from root.
        self.reset()

        # Go down to the first leaf.
        while self.can_move_down():
            self.down()

        # Traverse forever (or until we break on some ending condition).
        while True:

            # Yield the current node.
            yielded_node = self._current_node()
            yield yielded_node

            # If we yielded None, then iteration had fallen off the end of some
            # list. If the current node is still None after yielding, then it
            # was not replaced. Go up to the next level to prevent traversal
            # from yielding empty indices forever. Stop traversal if we cannot
            # go up anymore.
            if yielded_node is None and self._current_node() is None:
                if self.can_move_up():
                    self.up()
                else:
                    return
            # If traversal can move to the next sibling, do so, then move down
            # as far as possible.
            elif self.can_move_next():
                self.next()
                while self.can_move_down():
                    self.down()
            # If nothing else, go up. Stop traversal if we cannot go up
            # anymore.
            else:
                if self.can_move_up():
                    self.up()
                else:
                    return


def search_for_mapping(s1: Strace,
                       s2: Strace,
                       gen: Generator[ValidationResult, Validatable, None],
                       mapping: Optional[ParameterMapping] = None,
                       ) -> Tuple[MigrationResult, ValidationResult]:
    """Search for the optimal mapping to migrate ``s1`` to ``s2``.

    Search is performed by producing and validating migrations of ``s1`` based
    on ``s2`` with different parameter mappings. The migration with the best
    validation score is returned.

    Parameters
    ----------
    s1 : Strace
        Source Strace.
    s2 : Strace
        Target Strace.
    gen : Generator[ValidationResult, Validatable, None]
        Validation generator that is ready to receive a new executable via
        ``send`` and yield a validation result.
    mapping : Optional[ParameterMapping]
        An optional parameter mapping. If provided, the search will start with
        the parameter mapping. If not provided, search will start with
        no mapping.

    Returns
    -------
    Tuple[MigrationResult, ValidationResult]
        The best migration and its validation result.
    """
    logger.info(f'Validating `{s2.executable_repr}`')

    # Run the initial validation.
    validation = gen.send(s2)
    logger.info(f'Score: `{validation.score}`')

    # Get parameters, and map backwards.
    source_parameters = {
        param.key: param
        for param in ExecutableParameter.get_parameters(s1)
    }
    source_parameter_keys = set(source_parameters.keys())
    target_parameters = {
        param.key: param
        for param in ExecutableParameter.get_parameters(s2)
    }

    # If at least one of the executables doesn't have parameters, skip trying
    # to improve the mapping.
    if not source_parameters or not target_parameters:
        result = MigrationResult(
            source=s1,
            target=s2,
            mapping=mapping,
            migration=s2
        )
        return result, validation

    # Create a mapping tree and walker for the target arguments.
    target = copy(s2)
    tree = MappingTree.from_value(s2.arguments)
    walker = TreeWalker(tree, fall_off_lists=False)

    # TODO Maybe pull up to avoid re-validating after mapping.
    # TODO Add apt-cache to validation container?
    # Initialize from the mapping if one was provided, then re-validate.
    if mapping is not None:
        for src, dest in mapping:
            walker.down_to_key(dest)
            walker.map(src, source_parameters[src].parameter_value)
        s2.arguments = tree.to_value()
        validation = gen.send(s2)

    # Preprocessing: Perform a post-order traversal. For each node, check if it
    # can be replaced with a list containing the node. If it can, keep the
    # replacement. This check looks for and normalizes cases where arguments
    # will accept either a single item or a list of items.
    logger.info('Checking for list replacement.')
    if validation.exe_2_metadata.exit_code == 0:
        for node in walker.postorder_traversal():
            walker.replace(ListNode([node]))
            s2.arguments = tree.to_value()
            new_validation = gen.send(s2)

            # Undo if the new validation is not the same as the old one. We're
            # looking for replacements that achieve the exact same effect as
            # the original.
            if new_validation != validation:
                walker.replace(node)
                s2.arguments = tree.to_value()

    # Search: Perform a post-order traversal. For each node, pick a source
    # parameter that is not yet in the mapping or that can be pulled up and
    # map it. If the validation score increases, keep the mapping. Falling off
    # lists lets search add additional parameters to the end of lists.
    logger.info('Searching for mapping.')
    walker.fall_off_lists(True)
    for node in walker.postorder_traversal():
        available_keys = source_parameter_keys - tree.get_mapped_keys()
        # If the node is defined, add its mapped keys to the available keys.
        # This lets us attempt things like replacing a list containing an
        # element with the element itself.
        if node is not None:
            available_keys |= node.get_mapped_keys()
        for key in available_keys:
            walker.map(key, source_parameters[key].parameter_value)
            s2.arguments = tree.to_value()
            new_validation = gen.send(s2)

            if new_validation.score > validation.score:
                validation = new_validation
                break
            else:
                walker.unmap()
                s2.arguments = tree.to_value()
    walker.fall_off_lists(False)

    # Postprocessing: Perform a post-order traversal. For each node, remove the
    # node if doing so will increase the score.
    logger.info('Checking for attribute removal.')
    for node in walker.postorder_traversal():
        key, _ = walker.remove()
        s2.arguments = tree.to_value()
        new_validation = gen.send(s2)

        if new_validation.score > validation.score:
            validation = new_validation
        else:
            walker.insert_next(key, node)
            s2.arguments = tree.to_value()

    # Return the migration result.
    logger.info(f'Score: `{validation.score}`')
    result = MigrationResult(
        source=s1,
        target=target,
        mapping=tree.get_mapping(),
        migration=s2
    )
    return result, validation


def get_unique_migrations(strace: Strace,
                          results: Sequence[ScoringResult],
                          num_executables: int = DEFAULT_NUM_EXECUTABLES,
                          num_definitions: int = DEFAULT_NUM_DEFINITIONS,
                          ) -> List[MigrationResult]:
    """Get unique migrations from a sequence of scoring results.

    This returns the top n definitions for the top m executables in
    ``results``, for a maximum of n * m unique migrations. Less unique
    migrations may be produced if there are less than m executables, or less
    than n unique migrations within one of the top executables.

    Parameters
    ----------
    strace : Strace
        Source strace.
    results : Sequence[ScoringResult]
        A sequence of scoring results for ``strace`` compared to some other
        strace. Results may include parameter mappings.
    num_executables : int
        Number of top executables to include in unique migrations.
    num_definitions : int
        Number of top definitions from an executable to include.

    Returns
    -------
    List[MigrationResult]
        Unique migrations. The returned list of migrations will match the
        ordering of ``results``.
    """
    # Get n unique migrations for the top m executables.
    all_migrations = []
    executable_migrations = {}
    hashed_arguments = {}
    for result in results:

        # If the maximum number of executables have been encountered, and all
        # executables have the maximum number of definitions, stop processing.
        if (len(executable_migrations) == num_executables
                and all(definitions == num_definitions
                        for definitions in executable_migrations.values())):
            break

        # Reference the executable from the second strace.
        exe = result.s2.executable

        # If the maximum number of executables have been encountered, and the
        # current executable is not one of them, skip it.
        if (len(executable_migrations) == num_executables
                and exe not in executable_migrations):
            continue

        # Add defaults if this executable has not been encountered before.
        if exe not in executable_migrations:
            executable_migrations[exe] = 0
            hashed_arguments[exe] = set()

        # If the maximum number of definitions have been encountered for this
        # executable, skip it.
        if executable_migrations[exe] == num_definitions:
            continue

        migration_result = strace.migrate(result.s2, result.mapping)
        hashable_args = hashable_arguments_representation(
            migration_result.migration.arguments
        )
        if hashable_args not in hashed_arguments[exe]:
            all_migrations.append(migration_result)
            executable_migrations[exe] += 1
            hashed_arguments[exe].add(hashable_args)

    # Return the ordered list of all migrations.
    return all_migrations


def search_for_migration(strace: Strace,
                         results: Sequence[ScoringResult],
                         num_executables: int = DEFAULT_NUM_EXECUTABLES,
                         num_definitions: int = DEFAULT_NUM_DEFINITIONS,
                         setup: Optional[str] = None,) -> Tuple[
                             MigrationResult, ValidationResult]:
    """Search for the beset migration based on a sequence of scoring results.

    Parameters
    ----------
    strace : Strace
        Source strace.
    results : Sequence[ScoringResult]
        Sequence of comparison score results for ``strace``.
    num_executables : int
        Number of top executables to consider during search.
    num_definitions : int
        Number of top definitions to consider during search.
    setup : str
        Setup to perform before validating a migration.

    Returns
    -------
    Tuple[MigrationResult, ValidationResult]
        The migrated strace with the top validation score.
    """
    # Get the top unique migrations based on initial result data.
    migrations = get_unique_migrations(
        strace,
        results,
        num_executables=num_executables,
        num_definitions=num_definitions,
    )
    migrations_str = '\n'.join(
        f'    {result.migration.executable_repr}' for result in migrations
    )
    logger.info(
        f'Found {len(migrations)} initial unique migrations: \n'
        f'{migrations_str}'
    )

    # Create and start the validation generator.
    gen = validation_generator(strace, setup)
    next(gen)

    # For each migration, search for the best possible mapping and validate
    # the changes.
    best = None
    validation_score = None
    for result in migrations:

        logger.info(
            f'Searching for best mapping using original migration '
            f'`{result.migration.executable_repr}`.'
        )

        # Search for the best possible migration/mapping.
        migration_result, validation = search_for_mapping(
            result.source,
            result.migration,
            gen,
            mapping=result.mapping,
        )
        if best is None or validation.score > validation_score:
            best = (migration_result, validation)
            validation_score = validation.score

    return best
