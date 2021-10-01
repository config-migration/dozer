#!/usr/bin/env bash


# Run a command, recording environment metadata before and after the command
# is executed.
#
# Usage ./run_validation.sh <cmd>


VALIDATION_DIR="${VALIDATION_DIR:+"$(realpath $VALIDATION_DIR)"}"
VALIDATION_DIR="${VALIDATION_DIR:-/validation}"
PRE_DIR="$VALIDATION_DIR/pre"
POST_DIR="$VALIDATION_DIR/post"


# Environment variables
# Current processes
# Current working directory
get_metadata() {

  if [[ -z "$1" ]]; then
    echo "Must provide an output directory."
    exit 1
  fi

  out_dir="$1"

  ps -e -o args | tail -n +2 > "$out_dir/proc"
  pwd > "$out_dir/cwd"
  env > "$out_dir/env"

}


# Exit if no command was provided.
if [[ -z "$@" ]]; then
  echo 'A command must be provided.'
  exit 1
fi


# Make all validation directories.
mkdir -p "$PRE_DIR"
mkdir -p "$POST_DIR"


# Get pre-execution environment metadata.
get_metadata "$PRE_DIR"

# Execute the command and save the exit code.
eval "$@"
exit="$?"

# Perform cleanup for configuration systems.
/scripts/cleanup.sh

# Get post-execution environment metadata.
get_metadata "$POST_DIR"

# Exit with the same exit code as the command being validated.
exit "$exit"
