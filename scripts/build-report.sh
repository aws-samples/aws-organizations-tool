#!/bin/bash

echo "build start"
echo "############ reports:"

echo "##### run cmd: orgtool report --config ./organization/.orgtool/config.yaml"
{ # try
    orgtool report --config ./organization/.orgtool/config.yaml > ./orgtool-report.log && echo "##### cmd output:"
    #save your output
} || { # catch
    echo "##### cmd output (with error):"
    # save log for exception 
}
cat ./orgtool-report.log

echo "#### run cmd: awsaccounts report --config ./organization/.orgtool/config.yaml"
{ # try
    awsaccounts report --config ./organization/.orgtool/config.yaml > ./awsaccounts-report.log && echo "##### cmd output:"
    #save your output
} || { # catch
    echo "##### cmd output (with error):"
    # save log for exception 
}
cat ./awsaccounts-report.log
