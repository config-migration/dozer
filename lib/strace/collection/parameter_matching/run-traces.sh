#!/usr/bin/env bash

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


# Trace executables.
# Command group to redirect all output on stdout/stderr.
{

  # Linux executables
  trace linux-echo.txt echo linux-message-01
  trace linux-touch.txt touch /tmp/linux-filename-01 && rm /tmp/linux-filename-01
  touch /tmp/linux-filename-02 && trace linux-rm.txt rm -rf /tmp/linux-filename-02
  trace linux-useradd.txt useradd linux-username-01 && userdel linux-username-01
  useradd linux-username-02 && trace linux-userdel.txt userdel linux-username-02

  # Ansible modules
  # TODO Refactor to trace by running Ansible to be consistent with playbook traces.
  trace ansible-command-echo.txt python -m ansible.modules.commands.command '{"ANSIBLE_MODULE_ARGS": {"_raw_params": "echo ansible-message-01"}}'
  trace ansible-file-touch.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path": "/tmp/ansible-filename-01", "state": "touch"}}' && rm /tmp/ansible-filename-01
  touch /tmp/ansible-filename-02 && trace ansible-file-rm.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path": "/tmp/ansible-filename-02", "state": "absent"}}'
  trace ansible-user-add.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name": "ansible-username-01"}}' && userdel ansible-username-01
  useradd ansible-username-02 && trace ansible-user-del.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name": "ansible-username-02", "state": "absent"}}'

}


# Wait a second before exiting.
# This is a bit of a hack. Strace wasn't always writing the full trace file
# before Docker exited when run with -DDD, and I'm not sure why. This seems to
# give it enough time to finish whatever it's doing.
sleep 1
