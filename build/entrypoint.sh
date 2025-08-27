#!/usr/bin/env bash

set -e

echo "Waiting 60s for TrueNAS to start..."
sleep 60

/wait.sh "/exec.sh"
