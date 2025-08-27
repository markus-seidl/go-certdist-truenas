#!/usr/bin/env bash

set -e

echo "Using configuration file: $CERTDIST_YAML_PATH"
/certdist client "$CERTDIST_YAML_PATH"
