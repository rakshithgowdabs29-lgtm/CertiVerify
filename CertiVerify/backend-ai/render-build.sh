#!/usr/bin/env bash
# exit on error
set -o errexit

pip install --upgrade pip setuptools wheel
pip install --prefer-binary -r requirements.txt