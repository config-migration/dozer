"""Dozer libraries."""

# Imports
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Dict, List, MutableMapping, Optional, Set, Tuple
import inspect
import logging
import os

import sqlalchemy


# Project directories
LIB = Path(__file__).parent.absolute()
BASE_DIR = LIB.parent


# Create SQLAlchemy MySQL engine
# https://github.com/sqlalchemy/sqlalchemy/issues/4216#issuecomment-441940908
mysql_engine = sqlalchemy.create_engine(
    'mysql+pymysql://root@127.0.0.1:3306/dozer?charset=utf8mb4'
    '&binary_prefix=true',
    pool_recycle=3600,
)


class IndentedLoggingAdapter(logging.LoggerAdapter):
    """Indented logging adapter.

    This auto-indents your log messages based on the current frame.
    """

    # Frame constants.
    # Logger frames is the number of frames in the framelist that are from the
    # logging module when the current frame is for Logger.process.
    LOGGER_FRAMES = 3

    def __init__(self,
                 logger: logging.Logger,
                 extra: Dict[Any, Any],
                 indent_file_mask: Optional[Set[str]] = frozenset()):
        """Initialize the logging adapter.

        Parameters
        ----------
        logger : logging.Logger
            Logger to adapt.
        extra : Dict[Any, Any]
            Extra arguments.
        indent_file_mask : Set[str]
            A set of files which will not add to the message indentation
            if they show up in the outer frames. If a directory is specified,
            the mask will apply to all files and subdirectories. Files may be
            absolute or relative to the project root (BASE_DIR).
        """
        super().__init__(logger, extra)
        self.file_mask = set(map(
            lambda m: str((BASE_DIR / m).resolve()),
            indent_file_mask
        ))
        self.cwd = Path(os.getcwd())
        self.framelist: List[Tuple[int, Tuple[str, str]]] = []
        self.debug_straces = False
        self.debug_straces_context = nullcontext

    def _not_masked(self, filename: str) -> bool:
        """Determine if a filename has been masked.

        Parameters
        ----------
        filename : str
            Filename to check.

        Returns
        -------
        bool
            True if the file has not been masked.
        """
        # Resolve filename from working directory. This does nothing if
        # filename is already absolute.
        filename = str(self.cwd / filename)

        # Check to see if masked.
        for mask in self.file_mask:
            if filename.startswith(mask):
                return False
        return True

    def process(self,
                msg: str,
                kwargs: MutableMapping) -> Tuple[Any, MutableMapping]:
        """Process a log message.

        Parameters
        ----------
        msg : str
            Log message.
        kwargs : Dict[Any, Any]
            Extra arguments.

        Returns
        -------
        Tuple[str, Dict[Any, Any]]
            Processed message and extra arguments.
        """
        # Get all outer frames for the current frame. Note that this returns
        # frames in reverse order (most recent first, root last).
        framelist = list(filter(
            lambda f: self._not_masked(f.filename),
            inspect.getouterframes(inspect.currentframe())[
                self.LOGGER_FRAMES:
            ],
        ))

        # Number of times to indent the message.
        indent = 0

        # New framelist to save.
        newframelist = []

        # Process the common prefix between the old and current framelists.
        while self.framelist and framelist:

            # Get the current frame and take only the filename and function.
            _frame = framelist.pop()
            frame = (_frame.filename, _frame.function)

            # Get the old frame and whether or not it was logged.
            logged, oldframe = self.framelist.pop()

            # If the frames do not match, we're no longer on the common prefix.
            if frame != oldframe:
                break

            # Indent if the old frame had a log statement and save in the new
            # framelist.
            indent += logged
            newframelist.append((logged, oldframe))

        # If the current framelist is empty, that means it occurs on the path
        # of (or is the same as) the old framelist. In this case we've counted
        # one more indent than we actually want, so decrease by one. Otherwise,
        # add the remaining frames to the new framelist and note a log on the
        # last one.
        if not framelist:
            indent -= 1
        else:
            newframelist += [
                (0, (frameinfo.filename, frameinfo.function))
                for idx in range(len(framelist) - 1, 0, -1)
                if (frameinfo := framelist[idx])
            ]
            frameinfo = framelist[0]
            newframelist.append((1, (frameinfo.filename, frameinfo.function)))

        # Set the new framelist. Reversed so that it matches with getting
        # frames from inspect.
        self.framelist = list(reversed(newframelist))

        # Return message with potential indent.
        if indent > 0:
            return f'{"----" * (indent - 1)}---> {msg}', kwargs
        else:
            return msg, kwargs

    def debug_strace(self, strace):
        """Print an strace object representation to stdout."""
        # Should use isinstance, but this avoids circular import because the
        # strace module imports the logger.
        if self.debug_straces:
            with self.debug_straces_context():
                print('{}\n{}\n\n'.format(
                    strace.executable_repr,
                    '\n'.join(map(str, strace.trace_lines))
                ))


# Configure logging
logging.basicConfig(format='%(asctime)-15s %(message)s')
logger = IndentedLoggingAdapter(
    logging.getLogger(__name__),
    {},
    indent_file_mask={
        '<frozen importlib._bootstrap>',
        '<frozen importlib._bootstrap_external>',
        'dozer.py',
        'lib/subcommands',
    }
)
logger.setLevel(logging.INFO)
