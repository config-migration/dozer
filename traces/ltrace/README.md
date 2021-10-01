# Ansible

Ansible modules are tested on ansible==2.8.6 using the Docker image
python:3.8-slim-buster.

Docker run command (cwd: `traces/ltrace/ansible`):

```
docker run --rm -it -v "$(pwd):/traces" python:3.8-slim-buster bash
```

Setup:

```
apt-get update
apt-get install -y ltrace
pip install ansible==2.8.6
```

Strace Commands

- `ltrace -f --demangle -S -n4 -o /traces/command-echo.txt python -m ansible.modules.commands.command '{"ANSIBLE_MODULE_ARGS": {"_raw_params":"echo '"'"'Hello World'"'"'"}}'`
- `ltrace -f --demangle -S -n4 -o /traces/file-touch.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"touch"}}'`
- `ltrace -f --demangle -S -n4 -o /traces/file-rm.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"absent"}}'`
- `ltrace -f --demangle -S -n4 -o /traces/user-add.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser"}}'`
- `ltrace -f --demangle -S -n4 -o /traces/user-del.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser","state":"absent"}}'`

# Linux

Linux system utilities are the default installed on the Docker
debian:bullseye-slim image. Collection was run inside Docker.

Docker run command (cwd: `traces/ltrace/linux`):

```
docker run --rm -it -v "$(pwd):/traces" debian:bullseye-slim bash
```

Setup:

```
apt-get update
apt-get install -y ltrace
```

Strace Commands

- `ltrace -f --demangle -S -n4 -o /traces/echo.txt echo 'test'`
- `ltrace -f --demangle -S -n4 -o /traces/touch.txt touch /tmp/test`
- `ltrace -f --demangle -S -n4 -o /traces/rm.txt rm -rf /tmp/test`
- `ltrace -f --demangle -S -n4 -o /traces/useradd.txt useradd ExampleUser`
- `ltrace -f --demangle -S -n4 -o /traces/userdel.txt userdel ExampleUser`
