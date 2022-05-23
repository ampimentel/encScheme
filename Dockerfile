FROM ubuntu:18.04
MAINTAINER support@charm-crypto.com

ENV SEED=0
ENV PATH_MEASURES=/measures

RUN apt update && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev python3-setuptools libgmp-dev libssl-dev
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd /pbc-0.5.14 && ./configure LDFLAGS="-lgmp" && make && make install && ldconfig
COPY . /charm
RUN cd /charm && ./configure.sh && make && make install && ldconfig
CMD ["sh", "-c", "python3 charm/encScheme/encDb.py --seed=$SEED --pathMeasures=$PATH_MEASURES"]
#CMD ["echo",  "hello"]