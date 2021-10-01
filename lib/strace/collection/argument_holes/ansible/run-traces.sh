#!/usr/bin/env bash


# Variables
ITERATIONS=20
MAX_ROWS=50000
TRACE_DIR='/traces'


trace() {

  # Take the first argument as the output file for strace, then remove it
  # from the list of arguments.
  output_file="$TRACE_DIR/$1"
  shift

  # Run strace using the remaining aruments as the command.
  # -DDD    Run the tracer as a child of the traced process in a separate session.
  # -f      Trace child processes resulting from fork, vfork, and clone.
  # -y      Print file descriptor paths.
  # -yy     Print protocol information for socket file descriptors.
  # -X raw  Raw number output (no decoding).
  # -I 2    Block signals while decoding syscalls (kills tracer when awk exits).
  # -o      Print up to MAX_ROWS number or rows to the output file and exit.
  #         Print TRUNCATED if the entire trace is not printed.
  strace -DDD -f -y -yy -X raw -I 2 -o "| awk 'NR>$MAX_ROWS{print "\""TRUNCATED"\""; exit}; {print}' > $output_file" "$@"

}


# Make results directories
DIRS=(/traces/ansible-{command-echo,file-touch,file-rm,user-add,user-del})
rm -rf "${DIRS[@]}"
mkdir -p "${DIRS[@]}"


# Trace executables.
# Command group to redirect all output on stdout/stderr.
{

  # Exec traces for each iteraation
  for ((i=0; i<ITERATIONS; i++)); do

    # TODO Refactor to trace by running Ansible to be consistent with playbook traces.
    trace ansible-command-echo/$i.txt python -m ansible.modules.commands.command '{"ANSIBLE_MODULE_ARGS": {"_raw_params":"echo '"'"'test'"'"'"}}'
    trace ansible-file-touch/$i.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"touch"}}'
    trace ansible-file-rm/$i.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"absent"}}'
    trace ansible-user-add/$i.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser"}}'
    trace ansible-user-del/$i.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser","state":"absent"}}'

  done

}


# Wait a second before exiting.
# This is a bit of a hack. Strace wasn't always writing the full trace file
# before Docker exited when run with -DDD, and I'm not sure why. This seems to
# give it enough time to finish whatever it's doing.
sleep 1
