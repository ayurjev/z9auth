FROM ubuntu:14.04
RUN apt-get update
RUN apt-get install -y \
    build-essential wget git libcurl4-gnutls-dev libexpat1-dev gettext libz-dev libssl-dev \
    libjpeg62-dev zlib1g-dev libfreetype6-dev liblcms1-dev

RUN wget https://www.python.org/ftp/python/3.5.1/Python-3.5.1.tgz && \
    tar -zxvf Python-3.5.1.tgz && cd Python-3.5.1 && \
    ./configure && make && make install
RUN pip3 install git+https://git@github.com/ayurjev/envi.git#egg=envi && \
    pip3 install git+https://git@github.com/ayurjev/suit.git#egg=suit && \
    pip3 install git+https://git@github.com/ayurjev/mapex.git#egg=mapex && \
    pip3 install uwsgi webtest requests pymongo

RUN echo '#!/bin/bash' >> /usr/local/bin/runtests && \
    echo 'python3 -m unittest discover /var/www/' >> /usr/local/bin/runtests && \
    chmod a+x /usr/local/bin/runtests

WORKDIR /var/www/
COPY . /var/www/
