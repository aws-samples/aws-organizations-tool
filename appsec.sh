#!/bin/bash

# move into the current script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $SCRIPT_DIR
echo $(pwd)

echo '#### pyflakes ./**/*.py'
pyflakes ./**/*.py

echo '#### flake8 --ignore E501,W605'
flake8 --ignore E501,W605

echo '#### cfn-lint ./automation/*.yaml'
cfn-lint ./automation/*.yaml 

echo '#### cfn_nag_scan --input-path ./**/*.yaml'
cfn_nag_scan --input-path ./**/*.yaml
