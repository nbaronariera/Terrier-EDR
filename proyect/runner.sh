#!/usr/bin/env bash

if [[ "$1" == *"/deps/"* ]]; then
    exec "$@"
else
    exec sudo -E "$@"
fi
