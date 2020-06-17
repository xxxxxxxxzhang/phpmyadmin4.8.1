FROM ubuntu:18.04

COPY ./poc/ /opt/poc/
COPY requirements_poc.txt /opt/poc/requirements_poc.txt
RUN sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN apt-get clean
RUN apt-get update --fix-missing && apt-get install -y\
  curl \
  python3 \
  python3-pip \
  firefox
RUN pip3 install -r /opt/poc/requirements_poc.txt
CMD bash /opt/poc/poc.sh