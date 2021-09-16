#!/bin/bash

echo "############ apply:"
set -e

echo "##### run cmd: orgtool organization --config ./organization/.orgtool/config.yaml --exec"
orgtool organization --config ./organization/.orgtool/config.yaml --exec

echo "##### run cmd: awsaccounts create --config ./organization/.orgtool/config.yaml --exec"
awsaccounts create --config ./organization/.orgtool/config.yaml --exec

echo "##### run cmd: awsaccounts update --config ./organization/.orgtool/config.yaml --exec"
awsaccounts update --config ./organization/.orgtool/config.yaml --exec
