#!/usr/bin/env bash

set -e

echo "Using configuration file: $PERSIST_DIR/config.yml"
/certdist client "$PERSIST_DIR/config.yml"
