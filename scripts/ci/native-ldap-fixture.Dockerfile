FROM ubuntu:24.04
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Run only inside the private fixture mount. The CI caller chooses an
# unprivileged numeric UID/GID and a loopback-published unprivileged port.
ENTRYPOINT ["/bin/sh", "-ec", "/usr/sbin/slapadd -f /fixture/slapd.conf -l /fixture/seed.ldif; exec /usr/sbin/slapd -f /fixture/slapd.conf -h ldaps://0.0.0.0:1636/ -d 1"]
