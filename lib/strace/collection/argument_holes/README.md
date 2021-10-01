# Ansible

Ansible modules are tested on ansible==2.8.6 using the Docker image
python:3.8-slim-buster.

Docker run command (cwd: `traces/strace/ansible`):

```
docker run --rm -it -v "$(pwd):/traces" python:3.8-slim-buster bash
```

Setup:

```
apt-get update
apt-get install -y strace
pip install ansible==2.8.6
```

Strace Commands

- `strace -X raw -f -o /traces/command-echo.txt python -m ansible.modules.commands.command '{"ANSIBLE_MODULE_ARGS": {"_raw_params":"echo '"'"'test'"'"'"}}'`
- `strace -X raw -f -o /traces/file-touch.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"touch"}}'`
- `strace -X raw -f -o /traces/file-rm.txt python -m ansible.modules.files.file '{"ANSIBLE_MODULE_ARGS": {"path":"/tmp/test","state":"absent"}}'`
- `strace -X raw -f -o /traces/user-add.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser"}}'`
- `strace -X raw -f -o /traces/user-del.txt python -m ansible.modules.system.user '{"ANSIBLE_MODULE_ARGS": {"name":"ExampleUser","state":"absent"}}'`

If building and running the provided Dockerfile:

```
docker build -t dozer/ansible-strace:latest .
docker run --rm -it -v "$(pwd):/traces" dozer/ansible-strace
```

# Linux

Linux system utilities are the default installed on the Docker
debian:bullseye-slim image. Collection was run inside Docker.

Docker run command (cwd: `traces/strace/linux`):

```
docker run --rm -it -v "$(pwd):/traces" debian:bullseye-slim bash
```

Setup:

```
apt-get update
apt-get install -y strace
```

Strace Commands

- `strace -X raw -f -o /traces/echo.txt echo 'test'`
- `strace -X raw -f -o /traces/touch.txt touch /tmp/test`
- `strace -X raw -f -o /traces/rm.txt rm -rf /tmp/test`
- `strace -X raw -f -o /traces/useradd.txt useradd ExampleUser`
- `strace -X raw -f -o /traces/userdel.txt userdel ExampleUser`

If building and running the provided Dockerfile:

```
docker build -t dozer/linux-strace:latest .
docker run --rm -it -v "$(pwd):/traces" dozer/linux-strace
```
