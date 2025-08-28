#!/usr/bin/env bash

set -e

echo "This container is running as user $(id -u) and group $(id -g)"

echo "Write check to $PERSIST_DIR"
touch "$PERSIST_DIR/allowed_write_test"
ls -lah "$PERSIST_DIR"

echo "Waiting 60s for TrueNAS to start..."
sleep 60

echo "Run /exec.sh on off, in case TrueNAS wasn't running when the certificate was updated"

/exec.sh

/wait.sh "/exec.sh"
