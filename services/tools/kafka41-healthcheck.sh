#!/usr/bin/env bash
set -euo pipefail
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --command-config /etc/kafka/secrets/client.properties --list >/dev/null
