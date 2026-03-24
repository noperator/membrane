FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/membrane

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
