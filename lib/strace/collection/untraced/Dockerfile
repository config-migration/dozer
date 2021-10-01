FROM debian:buster


VOLUME /traces
WORKDIR /traces


ENTRYPOINT ["/run-trace.sh"]
COPY run-trace.sh /run-trace.sh


RUN apt-get update
RUN apt-get install -y strace=4.26-0.2
