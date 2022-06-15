#!/bin/bash
set -euox pipefail


git config user.name "${TECHNICAL_USER}"
git config user.email "${TECHNICAL_USER}@users.noreply.github.com"
git fetch
git checkout ${BRANCH_NAME}


pip install -U pip setuptools wheel pdoc
pip install -U .

pdoc src/airlock_gateway_rest_api_lib/airlock_gateway_rest_api_lib.py -o page