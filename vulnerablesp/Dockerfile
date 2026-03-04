FROM python:3.11-slim

RUN apt-get update -y && apt-get install -y \
    pkg-config \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    zlib1g-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . /vulnerableSP
WORKDIR /vulnerableSP

RUN pip install --no-cache-dir --upgrade pip setuptools
RUN pip install --no-cache-dir uwsgi
RUN pip install --no-cache-dir --force-reinstall --no-binary lxml lxml>=4.9.0
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir /vulnerableSP

EXPOSE 8000

WORKDIR /vulnerableSP/yogiSP
CMD ["uwsgi", "--ini", "vulnsp.ini"]
