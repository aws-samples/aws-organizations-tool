#!/usr/bin/env python
"""Generate default org access role in an invited account.
Run this with IAM credentials for invited account.

Creates role 'OrganizationAccountAccessRole' allowing users in
Org Master account 'AdministratorAccess' in invited account.

Usage:
  orgtool-accessrole --master_id ID [--exec]
  orgtool-accessrole --help
  orgtool-accessrole --version

Options:
  -m, --master_id ID    Master Account ID
  -h, --help            Show this help message and exit.
  -V, --version         Display version info and exit.
"""

import json
import boto3
from docopt import docopt

import orgtool
from orgtool.utils import lookup

ROLENAME = 'OrganizationAccountAccessRole'
DESCRIPTION = 'Organization Access Role'
POLICYNAME = 'AdministratorAccess'


def main():
    args = docopt(__doc__, version=orgtool.__version__)
    iam_client = boto3.client('iam')
    # assemble assume-role policy statement
    principal = "arn:aws:iam::%s:root" % args['--master_id']
    statement = dict(
            Effect='Allow',
            Principal=dict(AWS=principal),
            Action='sts:AssumeRole')
    policy_doc = json.dumps(dict(Version='2012-10-17', Statement=[statement]))
    # create role
    print("Creating role %s" % ROLENAME)
    if args['--exec']:
        iam_client.create_role(
                Description=DESCRIPTION,
                RoleName=ROLENAME,
                AssumeRolePolicyDocument=policy_doc)
    # attach policy to new role
    iam_resource = boto3.resource('iam')
    aws_policies = iam_client.list_policies(Scope='AWS', MaxItems=500)['Policies']
    policy_arn = lookup(aws_policies, 'PolicyName', POLICYNAME, 'Arn')
    role = iam_resource.Role(ROLENAME)
    try:
        role.load()
    except Exception:
        pass
    else:
        print("Attaching policy %s to %s" % (POLICYNAME, ROLENAME))
        if args['--exec'] and policy_arn:
            role.attach_policy(PolicyArn=policy_arn)


if __name__ == "__main__":
    main()
