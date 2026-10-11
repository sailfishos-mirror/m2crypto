FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        libssl-dev \
        openssl \
        swig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN make clean \
    && python -m pip install --no-cache-dir -r dev-requirements.txt \
    && make wheel \
    && DISTROBOX_ENTER_PATH=/src make check
