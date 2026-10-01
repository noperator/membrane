FROM golang:1.23.2-bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
COPY dns-proxy/ /src/dns-proxy/
RUN cd /src/dns-proxy && CGO_ENABLED=0 go build -o /dns-proxy .
COPY ebpf/ /src/ebpf/
COPY tracer/ /src/tracer/
RUN cd /src/tracer && go generate ./... && \
    CGO_ENABLED=0 go build -trimpath -o /tracer .

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    dnsutils \
    openssl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install mitmproxy==12.2.1 --break-system-packages

RUN mkdir -p /etc/membrane

COPY --from=builder /dns-proxy /usr/local/bin/dns-proxy
COPY --from=builder /tracer /usr/local/bin/tracer
COPY entrypoint.sh /entrypoint.sh
COPY addon.py /addon.py
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
