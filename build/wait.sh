#!/bin/bash

set -e

# The command to execute is passed as arguments to this script
if [ -z "$1" ]; then
    echo "Usage: $0 <command> [args...]"
    exit 1
fi

while true; do
    # Calculate seconds until the next midnight UTC
    SECS_TO_EXECUTION=$(date -u +%s | awk '{print 86400 - ($1 % 86400)}')

    echo "Waiting for ${SECS_TO_EXECUTION} seconds..."
    sleep "${SECS_TO_EXECUTION}"

    echo "Executing command: $@"
    "$@"

    # Sleep for a short period to ensure we don't run the command twice in the same second
    sleep 5
done
