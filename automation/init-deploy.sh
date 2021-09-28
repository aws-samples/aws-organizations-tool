#!/bin/bash

# Usage info
show_help() {
cat << EOF
Usage: ${0##*/} [-h] -r ROLE
Deploy configuration orgformation.yaml into a stack named "orgformation" into the targe master account.
To deploy the stack, the script create a temporary bucket (delated at the end of the execution) to store the initial commit of AWS CodeCommit repository created by the stack.
The deployment of the stack will trigger the run of the AWS CodePipeline, then the first execution of the AWS CodeBuild project.
The first execution of the AWS CodeBuild project will generate the AWS Organization configurations file and will commit them into the CodeCommit repository:
    organization/.orgtool/root/config.yaml
    organization/.orgtool/root/sepc.d/accounts.yaml
    organization/.orgtool/root/sepc.d/common.yaml
    organization/.orgtool/root/sepc.d/custom_policies.yaml
    organization/.orgtool/root/sepc.d/delegations.yaml
    organization/.orgtool/root/sepc.d/organizational_units.yaml
    organization/.orgtool/root/sepc.d/sc_policies.yaml


    -h          display this help and exit
    -r ROLE     AWS Role to assume from the Master AWS Account to get in the AWS Organization member's AWS Accounts
EOF
}

run_init_deploy() {


    echo "Create S3 bucket and zip file for repo initialization"
    # 90517be1-9f4b-570a-c4b1-924ea4593748
    uuid=$(od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}')
    bucket_name="tmp-${uuid//-/}"
    aws s3 mb s3://$bucket_name

    echo "zip ./README.md"
    zip source.zip $SCRIPT_DIR/README.md
    aws s3 cp ./source.zip s3://$bucket_name


    echo "Deploy orgformation stack with OrgAccessRoleName=$org_access_role_name"
    aws cloudformation deploy \
        --no-fail-on-empty-changeset \
        --template-file $SCRIPT_DIR/orgformation.yaml \
        --stack-name "orgformation" \
        --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM \
        --parameter-overrides \
        BranchName="main" \
        OrgAccessRoleName="$org_access_role_name" \
        CodeInitBucketName="$bucket_name" \


    deletebucket=$(aws s3 rb s3://$bucket_name --force)
    echo $deletebucket
    echo "done"

}

# Initialize context:
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# echo "SCRIPT_DIR is $SCRIPT_DIR"


# Initialize our own variables:
org_access_role_name=""

OPTIND=1
# Resetting OPTIND is necessary if getopts was used previously in the script.
# It is a good idea to make OPTIND local if you process options in a function.

while getopts hr: opt; do
    case $opt in
        h)
            show_help
            exit 0
            ;;
        r)  org_access_role_name=$OPTARG
            run_init_deploy
            exit 0
            ;;
        *)
            show_help >&2
            exit 1
            ;;    
    esac
done
shift "$((OPTIND-1))"   # Discard the options and sentinel --
show_help

# Everything that's left in "$@" is a non-option.
# printf 'org_access_role_name=<%s>\n' "$org_access_role_name"
# printf '<%s>\n' "$@"




