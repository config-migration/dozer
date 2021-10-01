"""Collect linux executables.

This executable collector extracts linux executables from Dockerfiles stored
in GitHub repos. Repos are expected to have a file named `Dockerfile` directly
at the project root.

Requires git to be installed on the system.
"""


# Imports
from contextlib import ExitStack
from itertools import chain
from pathlib import Path
from typing import List, Set, Tuple, Union
import argparse
import csv
import hashlib
import multiprocessing
import re
import shlex
import subprocess
import tempfile

from lib import BASE_DIR, logger
from lib.strace.tables import untraced_executables as t_untraced_executables


# Regex
FROM_INSTRUCTIONS = re.compile(r'^FROM', re.MULTILINE)
FROM_DEBIAN_INSTRUCTION = re.compile(r'^FROM (debian|ubuntu)', re.MULTILINE)


# Constants
DEFAULT_REPOS_FILE = (
    BASE_DIR / 'data/github-repos-with-debian-based-dockerfiles.csv'
)
SHELL_PUNCTUATION = {';', '|', '&'}


def _normalize_run_notation(run_command: str) -> Set[Tuple[str, ...]]:
    """Normalize run command notation.

    Parameters
    ----------
    run_command : str
        Run command string.

    Returns
    -------
    Set[Tuple[str, ...]]
        Parsed commands.
    """
    # Remove newlines
    run_command = run_command.replace('\\\n', '')

    # Check to see if run command is in exec form
    match = re.match(r'\["([^"]*)"(?: *, *"([^"]*)")*\]', run_command)

    # If it matches, find all quoted commands
    if match:
        run_command = ' '.join(re.findall(r'"([^"]*)"', run_command))

    # Split into separate commands
    lexer = shlex.shlex(run_command, punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    cmd_list = list(lexer)
    return _split_cmd_list(cmd_list)


def _split_cmd_list(cmd_list: List[str]) -> Set[Tuple[str, ...]]:
    """Split a command into multiple commands by punctuation.

    Parameters
    ----------
    cmd_list : List[str]
        Command list.

    Returns
    -------
    Set[Tuple[str, ...]]
    """
    cmds = []
    cmd = []
    for part in cmd_list:
        if len(set(part)) == 1 and part[0] in SHELL_PUNCTUATION:
            if cmd:
                cmds.append(tuple(cmd))
            cmd = []
        else:
            cmd.append(part)
    if cmd:
        cmds.append(tuple(cmd))
    return set(cmds)


def clone_repo(repo: str, location: Union[Path, str]):
    """Clone a repo to a specified location.

    Parameters
    ----------
    repo : str
        Repo name.
    location : Union[Path, str]
        Location to clone the repo to.
    """
    # Format clone command
    cmd = [
        'git',
        'clone',
        '--depth=1',
        f'https://github.com/{repo}.git',
        str(location)
    ]

    # Clone
    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        logger.error(f'Failed to clone repo {repo}')
        raise


def get_dockerfile_contents(repo: str) -> str:
    """Get the contents of a Dockerfile from a repo.

    Parameters
    ----------
    repo : str
        Repo name.

    Returns
    -------
    str
        Dockerfile contents.
    """
    # Create exit stack context
    with ExitStack() as stack:

        # Enter temporary directory context
        temp_dir = stack.enter_context(tempfile.TemporaryDirectory())

        # Clone the repo into the temporary directory
        clone_repo(repo, temp_dir)

        # Get Dockerfile path
        dockerfile = Path(temp_dir) / 'Dockerfile'

        # Error if the repository does not provide a Dockerfile
        if not dockerfile.exists():
            raise ValueError('Repo does not have a Dockerfile')

        # Open dockerfile for reading
        dockerfile_fd = stack.enter_context(open(dockerfile))

        # Return contents
        return dockerfile_fd.read()


def get_repos_from_file(repos_file: Path) -> Set[str]:
    """Get all repos from a repos file.

    Parameters
    ----------
    repos_file : Path
        Path to a csv file containing GitHub repos. It must have a `repo`
        column with a repo in the <username>/<repo_name> format.

    Returns
    -------
    Set[str]
        Set of all repos in the repos file.
    """
    # Normalize to an absolute path based on cwd.
    repos_file = Path.cwd() / repos_file

    # Open file
    with open(repos_file) as repos_file_fd:

        # Create reader
        reader = csv.DictReader(repos_file_fd)

        # Construct set of repos
        return set(r['repo'] for r in reader)


def insert_untraced_executables(executables: Set[Tuple[str, ...]]):
    """Insert untraced executables into the Dozer database.

    Parameters
    ----------
    executables : Set[Tuple[str, ...]]
        Executables to insert.
    """
    # Process all executables
    for executable in executables:

        # Get the binary (executable) name and arguments
        # Convert arguments to a list
        binary, *arguments = executable
        arguments = list(arguments)

        # Hash arguments
        arguments_sha1 = (
            hashlib
            .sha1(repr(arguments).encode('utf-8'))
            .digest()
        )

        # Insert into the database
        t_untraced_executables.insert({
            'system': 'linux',
            'executable': binary,
            'arguments_hash': arguments_sha1,
            'arguments': arguments,
        }).execute()


def parse_dockerfile(dockerfile: str) -> Set[Tuple[str, ...]]:
    """Parse a Dockerfile for executables in run commands.

    Parameters
    ----------
    dockerfile : str
        Dockerfile contents

    Returns
    -------
    Set[Tuple[str, ...]]
        Set of parsed executables.
    """
    # Match all run commands
    # This includes multiline commands which included an escaped newline
    # Then normalize each command
    return set(chain(*map(
        _normalize_run_notation,
        re.findall(
            r'^RUN +([^\\\n]*(?:\\(?:.|\n)[^\\\n]*)*)',
            dockerfile,
            re.MULTILINE
        )
    )))


def parse_executables_from_file(repos_file: Path):
    """Parse executables from a set of repositories specified in a csv file.

    Parameters
    ----------
    repos_file : Path
        Path to a csv file containing GitHub repos. It must have a `repo`
        column with a repo in the <username>/<repo_name> format.
    """
    # Load repository definitions.
    repos = get_repos_from_file(repos_file)

    # Parse executables from repos
    parse_executables_from_repos(repos)


def parse_executables_from_repos(repos: Set[str]):
    """Parse executables from a set of repositories.

    Parameters
    ----------
    repos : Set[str]
        Set of GitHub repositories in the
    """
    # Sort repos for easy tracking.
    repos = list(sorted(repos))

    # Number of processes to run.
    # 2n + 1 is inspired by the Gunicorn default for workers.
    procs = 2 * multiprocessing.cpu_count() + 1

    # Process all repositories
    with multiprocessing.Pool(procs) as pool:
        pool.map(parse_executables_from_repo, repos)


def parse_executables_from_repo(repo: str):
    """Parse executables from a repository.

    Parameters
    ----------
    repo : str
        GitHub repository.
    """
    try:

        logger.info(f'Processing repo {repo}')

        # Get Dockerfile contents
        dockerfile = get_dockerfile_contents(repo)

        # Error if the Dockerfile is not for a single stage Debian build
        from_instructions = FROM_INSTRUCTIONS.findall(dockerfile)
        from_debian_instruction = FROM_DEBIAN_INSTRUCTION.match(dockerfile)
        if len(from_instructions) > 1 or not from_debian_instruction:
            raise ValueError(
                'Repo Dockerfile is not a single stage Debian build'
            )

        # Parse dockerfile contents
        executables = parse_dockerfile(dockerfile)

        # Insert executables into database
        insert_untraced_executables(executables)

    except Exception:

        logger.exception(f'Failed to parse executables from {repo}')


def main():
    """Collect trace information."""
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'repos_file',
        type=Path,
        default=DEFAULT_REPOS_FILE,
        nargs='?',
        help='Path to a csv file containing GitHub repos. It must have a '
             '`repo` column with a repo in the <username>/<repo_name> format.'
    )
    argv = parser.parse_args()

    # Parse
    parse_executables_from_file(
        repos_file=argv.repos_file,
    )


if __name__ == '__main__':
    main()
