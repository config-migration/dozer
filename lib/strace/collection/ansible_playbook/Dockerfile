# dozer/strace-collector-ansible-playbook
#
# Docker image for the Ansible playbook strace collector script. The image
# entrypoint is configured to run this script with an output directory mounted
# at the /output volume and the playbook file bind mounted at /playbook.yml.


# Base image on the official python image.
FROM python:3.8-buster


# Create output and source volumes.
VOLUME /output
VOLUME /source
WORKDIR /traces


# Set script entrypoint.
ENTRYPOINT ["python", "/collect.py", "--output-dir=/output", "--source-dir=/source"]


# Update apt cache and install strace, ansible, and collect.py dependencies.
RUN apt-get update
RUN apt-get install -y strace=4.26-0.2
RUN pip install ansible==2.9.2 pyyaml==5.2


# Add a debops configuration for default playbooks.
# https://github.com/moby/moby/issues/1297#issuecomment-375137941
# https://bugs.launchpad.net/ubuntu/+source/openssh/+bug/45234
RUN apt-get install -y build-essential libffi-dev libssl-dev libsasl2-dev libldap2-dev
RUN pip install debops[ansible]==1.2.0
RUN ln -s /usr/local/lib/python3.8/site-packages/debops/ansible/ /debops-ansible
RUN echo 'resolvconf resolvconf/linkify-resolvconf boolean false' | debconf-set-selections
RUN mkdir /run/sshd
ENV USER root


# Copy collect script.
COPY collect.py /collect.py
