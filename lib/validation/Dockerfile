FROM python:3.8-buster

# The Docker Python image doens't play well with deb installed packages.
#
# See:
# - https://github.com/docker-library/python/issues/43#issuecomment-153167501
# - https://stackoverflow.com/a/36232975/8588856

ENV PYTHONPATH=/usr/lib/python3/dist-packages
COPY apt-proxy.sh /proxy-scripts/apt-proxy.sh
RUN apt-get update
RUN apt-get install -y strace=4.26-0.2 python3-apt=1.8.4.1 net-tools netcat
RUN /proxy-scripts/apt-proxy.sh 3142
RUN cd /usr/lib/python3/dist-packages \
    && ln -s apt_inst.cpython-37m-x86_64-linux-gnu.so apt_inst.so \
    && ln -s apt_pkg.cpython-37m-x86_64-linux-gnu.so apt_pkg.so
RUN pip install ansible==2.9.2
COPY cleanup.sh /scripts/cleanup.sh
RUN /scripts/cleanup.sh
COPY run_validation.sh /scripts/run_validation.sh
