#!/bin/bash

echo "Deploy/Update orgformation stack"
echo "Check orgformation stack status"

FullStackName=orgformation

echo "cloudformation stack status for orgformation ..."
stackStatus=$(aws cloudformation describe-stacks --region ${AWS_REGION} --stack-name $FullStackName | jq -c -r .Stacks[0].StackStatus)
echo "stack status is $stackStatus"

if [ "$stackStatus" = "CREATE_COMPLETE" ] \
    || [ "$stackStatus" = "DELETE_COMPLETE" ] \
    || [ "$stackStatus" = "ROLLBACK_COMPLETE" ] \
    || [ "$stackStatus" = "UPDATE_COMPLETE" ] \
    || [ "$stackStatus" = "UPDATE_ROLLBACK_COMPLETE" ]; then

    aws cloudformation deploy \
    --no-fail-on-empty-changeset \
    --template-file ./automation/orgformation.yaml \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM \
    --stack-name $FullStackName \


else
    echo "$FullStackName is currently in status $stackStatus and can not be updated"
fi