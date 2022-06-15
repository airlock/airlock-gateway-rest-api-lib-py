#!/bin/bash
set -euox pipefail

set git config...
git config user.name "${TECHNICAL_USER}"
git config user.email "${TECHNICAL_USER}@users.noreply.github.com"
git fetch
git checkout ${BRANCH_NAME}

# install python requirements...
pip install -U pip setuptools wheel pdoc
pip install -U .

# create api doc
pdoc src/airlock_gateway_rest_api_lib/airlock_gateway_rest_api_lib.py -o docs

# commit doc changes..
if [ $(git status docs -s | wc -l) -gt 0 ]
then
    git add docs
    git commit -m "Automated API doc generation"
    git push "https://${TECHNICAL_USER}:${TECHNICAL_USER_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" ${BRANCH_NAME}
fi
