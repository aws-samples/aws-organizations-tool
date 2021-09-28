#!/bin/bash


echo "############ apply:"

echo "##### run cmd: orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec"
orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec

echo "##### run cmd: orgtool organization --config ./organization/.orgtool/root/config.yaml --exec"
orgtool organization --config ./organization/.orgtool/root/config.yaml --exec

echo "##### run cmd: orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec"
orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec

echo "##### run cmd: orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec"
orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec
