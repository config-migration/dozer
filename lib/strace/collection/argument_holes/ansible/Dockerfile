FROM python:3.8-buster

VOLUME /traces
WORKDIR /traces


CMD /run-traces.sh


RUN apt-get update
RUN apt-get install -y strace=4.26-0.2
RUN pip install ansible==2.9.2


COPY run-traces.sh /run-traces.sh

