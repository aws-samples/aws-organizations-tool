#!/usr/bin/env python


"""Manage users, group, and roles for cross account authentication in an
AWS Organization.

Usage:
  orgtoolauth (users|delegations|local-users|report) [--config FILE]
                                                     [--spec-dir PATH]
                                                     [--master-account-id ID]
                                                     [--auth-account-id ID]
                                                     [--org-access-role ROLE]
                                                     [--disable-expired]
                                                     [--opt-ttl HOURS]
                                                     [--users --roles --credentials]
                                                     [--account NAME] [--full]
                                                     [--exec] [-q] [-d|-dd]
  orgtoolauth (--help|--version)

Modes of operation:
  users         Provision users, groups and group membership.
  delegations   Provision policies and roles for cross account access.
  local-users   Provision local IAM users and policies in accounts.
  report        Display provisioned resources.

Options:
  -h, --help                Show this help message and exit.
  -V, --version             Display version info and exit.
  --config FILE             AWS Org config file in yaml format.
  --spec-dir PATH           Location of AWS Org specification file directory.
  --master-account-id ID    AWS account Id of the Org master account.
  --auth-account-id ID      AWS account Id of the authentication account.
  --org-access-role ROLE    IAM role for traversing accounts in the Org.
  --exec                    Execute proposed changes to AWS accounts.
  -q, --quiet               Repress log output.
  -d, --debug               Increase log level to 'DEBUG'.
  -dd                       Include botocore and boto3 logs in log stream.

  users options:
  --disable-expired         Delete profile if one-time-password
                            exceeds --opt-ttl.
  --opt-ttl HOURS           One-time-password time to live in hours
                            [default: 24].
  report options:
  --users                   Print user and groups report.
  --roles                   Print roles and custom policies report.
  --credentials             Print IAM credentials report.
  --full                    Print full details in reports.
  --account NAME            Just report for a single named account.

"""

import sys
import json

import boto3
from docopt import docopt

import orgtool
import orgtool.orgs
from orgtool.orgs import validate_accounts_unique_in_org_deployed
from orgtool.utils import get_assume_role_credentials, yamlfmt, string_differ, queue_threads, get_logger, validate_master_id, scan_deployed_accounts
from orgtool.loginprofile import validate_user, validate_login_profile, onetime_passwd_expired
from orgtool.spec import load_config, validate_spec
from orgtool.reports import report_maker, user_group_report, role_report, credentials_report, account_authorization_report


def expire_users(log, args, deployed, auth_spec, credentials):
    """
    Delete login profile for any users whose one-time-password has expired
    """
    for name in [u['UserName'] for u in deployed['users']]:
        user = validate_user(name, credentials)
        if user:
            login_profile = validate_login_profile(user)
            if login_profile and onetime_passwd_expired(log, user, login_profile, int(args['--opt-ttl'])):
                log.info('deleting login profile for user %s' % user.name)
                if args['--exec']:
                    login_profile.delete()


def delete_user(user, iam_client):
    """
    Strip user attributes and delete user.  Attributes include:

        Access keys (DeleteAccessKey)
        Attached managed policies (DetachUserPolicy)
        Group memberships (RemoveUserFromGroup)
        Multi-factor authentication (MFA) device (DeactivateMFADevice, DeleteVirtualMFADevice)
        Inline policies (DeleteUserPolicy)
        Signing certificate (DeleteSigningCertificate)
        Password (DeleteLoginProfile)
        SSH public key (DeleteSSHPublicKey)
        Git credentials (DeleteServiceSpecificCredential)

    :param: user
    :type:  boto3 iam User resource object
    """
    try:
        user.load()
    except user.meta.client.exceptions.NoSuchEntityException:
        return
    for x in user.access_keys.all():
        x.delete()
    for x in user.attached_policies.all():
        x.detach_user(UserName=user.name)
    for x in user.groups.all():
        x.remove_user(UserName=user.name)
    for x in user.mfa_devices.all():
        x.disassociate()
    for x in user.policies.all():
        x.delete()
    for x in user.signing_certificates.all():
        x.delete()
    profile = user.LoginProfile()
    try:
        profile.load()
        profile.delete()
    except profile.meta.client.exceptions.NoSuchEntityException:
        pass
    response = iam_client.list_ssh_public_keys(
        UserName=user.name,
    )
    if 'SSHPublicKeys' in response and response['SSHPublicKeys']:
        for key in response['SSHPublicKeys']:
            iam_client.delete_ssh_public_key(
                UserName=user.name,
                SSHPublicKeyId=key['SSHPublicKeyId'],
            )
    response = iam_client.list_service_specific_credentials(
        UserName=user.name,
    )
    if 'ServiceSpecificCredentials' in response and response['ServiceSpecificCredentials']:
        iam_client.delete_service_specific_credential(
            UserName='string',
            ServiceSpecificCredentialId=response['ServiceSpecificCredentials']['ServiceSpecificCredentialId'],
        )

    user.delete()


def delete_policy(policy):
    """
    Delete IAM policy.

    Args:
        policy (obj): boto3 IAM resource object
    """
    if policy.attachment_count > 0:
        for group in policy.attached_groups.all():
            policy.detach_group(GroupName=group.name)
        for user in policy.attached_users.all():
            policy.detach_user(UserName=user.name)
        for role in policy.attached_roles.all():
            policy.detach_role(RoleName=role.name)
    for version in policy.versions.all():
        if not version.is_default_version:
            version.delete()
    policy.delete()


def update_user_tags(iam_client, user, tags):
    if user.tags is not None:
        iam_client.untag_user(
            UserName=user.name,
            TagKeys=[tag['Key'] for tag in user.tags],
        )
    if tags is not None:
        iam_client.tag_user(
            UserName=user.name,
            Tags=tags,
        )


def create_users(credentials, args, log, deployed, auth_spec):
    """
    Manage IAM users based on user specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    for u_spec in auth_spec['users']:
        tags = [
            {'Key': 'cn', 'Value': u_spec['CN']},
            {'Key': 'email', 'Value': u_spec['Email']}
        ]
        # RequestId is not required
        if 'RequestId' in u_spec and u_spec['RequestId']:
            tags += [{'Key': 'request_id', 'Value': u_spec['RequestId']}]

        path = orgtool.utils.munge_path(auth_spec['default_path'], u_spec)
        deployed_user = orgtool.utils.lookup(deployed['users'], 'UserName', u_spec['Name'])
        if deployed_user:
            user = iam_resource.User(u_spec['Name'])
            # delete user
            if orgtool.utils.ensure_absent(u_spec):
                log.info("Deleting user '%s'" % user.name)
                if args['--exec']:
                    delete_user(user, iam_client)
            # update user
            elif user.path != path:
                log.info("Updating path for user '%s'" % u_spec['Name'])
                if args['--exec']:
                    user.update(NewPath=path)
            elif user.tags != tags:
                log.info("Updating tags for user '%s'" % u_spec['Name'])
                if args['--exec']:
                    update_user_tags(iam_client, user, tags)
        # create new user
        elif not orgtool.utils.ensure_absent(u_spec):
            log.info("Creating user '%s'" % u_spec['Name'])
            if args['--exec']:
                response = iam_client.create_user(
                    UserName=u_spec['Name'],
                    Path=path,
                    Tags=tags,
                )
                log.info(response['User']['Arn'])
                deployed['users'].append(response['User'])


def create_groups(credentials, args, log, deployed, auth_spec):
    """
    Manage IAM groups based on group specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    for g_spec in auth_spec['groups']:
        path = orgtool.utils.munge_path(auth_spec['default_path'], g_spec)
        deployed_group = orgtool.utils.lookup(deployed['groups'], 'GroupName', g_spec['Name'])
        if deployed_group:
            group = iam_resource.Group(g_spec['Name'])
            # delete group?
            if orgtool.utils.ensure_absent(g_spec):
                # check if group has users
                if list(group.users.all()):
                    log.error("Can not delete group '%s'. Still contains users" % g_spec['Name'])
                else:
                    log.info("Deleting group '%s'" % g_spec['Name'])
                    if args['--exec']:
                        for policy in group.policies.all():
                            policy.delete()
                        for policy in group.attached_policies.all():
                            policy.detach_group(GroupName=g_spec['Name'])
                        group.delete()
                        deployed['groups'].remove(deployed_group)
            # update group?
            elif group.path != path:
                log.info("Updating path on group '%s'" % g_spec['Name'])
                if args['--exec']:
                    group.update(NewPath=path)
        # create group
        elif not orgtool.utils.ensure_absent(g_spec):
            log.info("Creating group '%s'" % g_spec['Name'])
            if args['--exec']:
                response = iam_client.create_group(GroupName=g_spec['Name'], Path=path)
                log.info(response['Group']['Arn'])
                deployed['groups'].append(response['Group'])


def manage_group_members(credentials, args, log, deployed, auth_spec):
    """
    Populate users into groups based on group specification.
    """
    iam_resource = boto3.resource('iam', **credentials)
    for g_spec in auth_spec['groups']:
        if orgtool.utils.lookup(deployed['groups'], 'GroupName', g_spec['Name']):
            group = iam_resource.Group(g_spec['Name'])
            current_members = [user.name for user in group.users.all()]
            # build list of specified group members
            spec_members = []
            if 'Members' in g_spec and g_spec['Members']:
                if g_spec['Members'] == 'ALL':
                    # all managed users except when user ensure: absent
                    spec_members = [user['Name'] for user in auth_spec['users'] if not orgtool.utils.ensure_absent(user)]
                    if 'ExcludeMembers' in g_spec and g_spec['ExcludeMembers']:
                        spec_members = [user for user in spec_members if user not in g_spec['ExcludeMembers']]
                else:
                    # just specified members
                    for username in g_spec['Members']:
                        u_spec = orgtool.utils.lookup(auth_spec['users'], 'Name', username)
                        # not a managed user?
                        if not u_spec:
                            log.error("User '%s' not in auth_spec['users']. Can not add user to group '%s'" % (username, g_spec['Name']))
                        # managed but absent?
                        elif orgtool.utils.ensure_absent(u_spec):
                            log.error("User '%s' is specified 'absent' in auth_spec['users']. Can not add user to group '%s'" % (username, g_spec['Name']))
                        else:
                            spec_members.append(username)
            # ensure all specified members are in group
            if not orgtool.utils.ensure_absent(g_spec):
                for username in spec_members:
                    if username not in current_members:
                        log.info("Adding user '%s' to group '%s'" % (username, g_spec['Name']))
                        if args['--exec']:
                            group.add_user(UserName=username)
            # ensure no unspecified members are in group
            for username in current_members:
                if username not in spec_members:
                    log.info("Removing user '%s' from group '%s'" % (username, g_spec['Name']))
                    if args['--exec']:
                        group.remove_user(UserName=username)


def manage_group_policies(credentials, args, log, deployed, auth_spec):
    """
    Attach managed policies to groups based on group specification
    """
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    auth_account = orgtool.utils.lookup(deployed['accounts'], 'Id', auth_spec['auth_account_id'], 'Name')
    log.debug("auth account: '%s'" % auth_account)
    for g_spec in auth_spec['groups']:
        if (orgtool.utils.lookup(deployed['groups'], 'GroupName', g_spec['Name']) and not orgtool.utils.ensure_absent(g_spec)):
            log.debug("processing group spec for '%s':\n%s" % (g_spec['Name'], g_spec))
            group = iam_resource.Group(g_spec['Name'])
            attached_policies = [p.policy_name for p in list(group.attached_policies.all())]
            log.debug("attached policies: '%s'" % attached_policies)
            if 'Policies' not in g_spec or g_spec['Policies'] is None:
                g_spec['Policies'] = []
            if g_spec['Policies']:
                log.debug("specified policies: '%s'" % g_spec['Policies'])
                # attach missing policies
                for policy_name in g_spec['Policies']:
                    if policy_name not in attached_policies:
                        policy_arn = get_policy_arn(iam_client, policy_name)
                        if policy_arn is None:
                            policy_arn = manage_custom_policy(iam_client, auth_account, policy_name, args, log, auth_spec)
                        log.debug("policy Arn for '%s': %s" % (policy_name, policy_arn))
                        log.info("Attaching policy '%s' to group '%s' in account '%s'" % (policy_name, g_spec['Name'], auth_account))
                        if args['--exec']:
                            group.attach_policy(PolicyArn=policy_arn)
                    # update custom policy
                    elif orgtool.utils.lookup(auth_spec['custom_policies'], 'PolicyName', policy_name):
                        manage_custom_policy(iam_client, auth_account, policy_name, args, log, auth_spec)
            # datach obsolete policies
            for policy_name in attached_policies:
                if policy_name not in g_spec['Policies']:
                    policy_arn = get_policy_arn(iam_client, policy_name)
                    log.info("Detaching policy '%s' from group '%s' in account '%s'" % (policy_name, g_spec['Name'], auth_account))
                    if args['--exec']:
                        group.detach_policy(PolicyArn=policy_arn)


def get_policy_arn(iam_client, policy_name):
    """
    Return the policy arn of the named IAM policy in an account.
    """
    aws_policies = orgtool.utils.get_iam_objects(iam_client.list_policies, 'Policies')
    return orgtool.utils.lookup(aws_policies, 'PolicyName', policy_name, 'Arn')


def manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec):
    """
    Create or update a custom IAM policy in an account based on a
    policy specification.  Returns the policy arn.
    """
    log.debug("account: '{}', policy_name: '{}'".format(account_name, policy_name))
    p_spec = orgtool.utils.lookup(auth_spec['custom_policies'], 'PolicyName', policy_name)
    if not p_spec:
        log.error("Custom Policy spec for '%s' not found in auth-spec." % policy_name)
        log.error("Policy creation failed.")
        return None
    policy_doc = dict(Version='2012-10-17', Statement=p_spec['Statement'])

    # check if custom policy exists
    custom_policies = orgtool.utils.get_iam_objects(iam_client.list_policies, 'Policies', dict(Scope='Local'))
    log.debug("account: '%s', custom policies: '%s'" % (account_name, [p['Arn'] for p in custom_policies]))
    policy = orgtool.utils.lookup(custom_policies, 'PolicyName', policy_name)
    if not policy:
        log.info("Creating custom policy '%s' in account '%s':\n%s" % (policy_name, account_name, yamlfmt(policy_doc)))
        if args['--exec']:
            return iam_client.create_policy(
                PolicyName=policy_name,
                Path=orgtool.utils.munge_path(auth_spec['default_path'], p_spec),
                Description=p_spec['Description'],
                PolicyDocument=json.dumps(policy_doc),
            )['Policy']['Arn']
        return None

    # check if custom policy needs updating
    else:
        current_doc = iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
        log.debug("account: '%s', policy_doc: %s" % (account_name, policy_doc))
        log.debug("account: '%s', current_doc: %s" % (account_name, current_doc))

        # compare each statement as dict
        update_required = False
        if current_doc['Statement'] != policy_doc['Statement']:
            update_required = True
            log.debug('account: %s, update_required: %s' % (account_name, update_required))

        # update policy and set as default version
        if update_required:
            log.info("Updating custom policy '%s' in account '%s':\n%s" % (policy_name, account_name, string_differ(yamlfmt(current_doc), yamlfmt(policy_doc))))
            if args['--exec']:
                log.debug("check for non-default policy versions for '%s'" % policy_name)
                for v in iam_client.list_policy_versions(
                        PolicyArn=policy['Arn'])['Versions']:
                    if not v['IsDefaultVersion']:
                        log.info("Deleting non-default policy version '%s' for policy '%s' in account '%s'" % (v['VersionId'], policy_name, account_name))
                        iam_client.delete_policy_version(PolicyArn=policy['Arn'], VersionId=v['VersionId'])
                iam_client.create_policy_version(PolicyArn=policy['Arn'], PolicyDocument=json.dumps(policy_doc), SetAsDefault=True)
        return policy['Arn']


def build_role_arn(account_id, d_spec, auth_spec):
    return 'arn:aws:iam::{}:role{}{}'.format(
        account_id,
        orgtool.utils.munge_path(auth_spec['default_path'], d_spec),
        d_spec['RoleName']
    )


def build_resource_list(log, deployed_accounts, d_spec, auth_spec, account_list):
    resource = []
    for account in account_list:
        account_id = orgtool.utils.lookup(deployed_accounts, 'Name', account, 'Id')
        if account_id is not None:
            resource.append(build_role_arn(account_id, d_spec, auth_spec))
        else:
            log.warn('Account {} not found in deployed accounts'.format(account))
    return resource


def assemble_assume_role_policy_document(resource, effect):
    statement = dict(
        Effect=effect,
        Action='sts:AssumeRole',
        Resource=resource,
    )
    return dict(Version='2012-10-17', Statement=[statement])


def create_group_policy(args, log, group, account, policy_name, policy_doc):
    log.info("Creating assume role policy '{}' for group '{}' in account '{}':\n{}".format(
        policy_name,
        group.name,
        account,
        yamlfmt(policy_doc),
    ))
    if args['--exec']:
        group.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
        )


def update_group_policy(args, log, group, account, policy_name, policy_doc):
    log.info("Updating policy '{}' for group '{}' in account '{}':\n{}".format(
        policy_name,
        group.name,
        account,
        string_differ(
            yamlfmt(group.Policy(policy_name).policy_document),
            yamlfmt(policy_doc),
        ),
    ))
    if args['--exec']:
        group.Policy(policy_name).put(PolicyDocument=json.dumps(policy_doc))


def manage_group_policy(args, log, group, account, policy_name, policy_doc, group_policies):
    if policy_name not in group_policies:
        create_group_policy(args, log, group, account, policy_name, policy_doc)
    elif group.Policy(policy_name).policy_document != policy_doc:
        update_group_policy(args, log, group, account, policy_name, policy_doc)


def delete_group_policy(args, log, group, account, policy_name):
    log.info("Deleting assume role group policy '{}' from group '{}' in account '{}'".format(
        policy_name,
        group.name,
        account,
    ))
    if args['--exec']:
        group.Policy(policy_name).delete()


def delete_obsolete_group_policy(args, log, group, account, policy_name, managed_policies):
    if policy_name not in managed_policies:
        log.info("Deleting obsolete policy '{}' from group '{}' in account '{}'".format(
            policy_name,
            group.name,
            account,
        ))
        if args['--exec']:
            group.Policy(policy_name).delete()


def set_group_assume_role_policies(args, log, deployed, auth_spec, d_spec):
    """
    Assign and manage assume role trust policies on IAM groups in
    Auth account.
    """
    log.debug('role: %s' % d_spec['RoleName'])
    credentials = get_assume_role_credentials(
        args['--auth-account-id'],
        args['--org-access-role'],
    )
    iam_resource = boto3.resource('iam', **credentials)
    auth_account = orgtool.utils.lookup(deployed['accounts'], 'Id', auth_spec['auth_account_id'], 'Name')
    managed_policies = []
    if orgtool.utils.lookup(deployed['groups'], 'GroupName', d_spec['TrustedGroup']):
        group = iam_resource.Group(d_spec['TrustedGroup'])
        group.load()
    else:
        log.error(
            "Can not manage assume role policy for delegation role '{}' in group '{}'. "
            "Group not found in auth account '{}'".format(
                d_spec['RoleName'],
                d_spec['TrustedGroup'],
                auth_account,
            )
        )
        return

    # make list of existing group policies which match this role name
    group_policies = [
        p.policy_name for p in list(group.policies.all())
        if p.policy_name.endswith(d_spec['RoleName'])
    ]

    # test if delegation should be deleted
    if orgtool.utils.ensure_absent(d_spec):
        for policy_name in group_policies:
            delete_group_policy(args, log, group, auth_account, policy_name)
        return

    # handle trusting accounts
    if d_spec['TrustingAccount'] == 'ALL':
        resource = build_role_arn('*', d_spec, auth_spec)
    else:
        resource = build_resource_list(
            log, deployed['accounts'], d_spec, auth_spec, d_spec['TrustingAccount']
        )
    policy_doc = assemble_assume_role_policy_document(resource, 'Allow')
    policy_name = "AllowAssumeRole-{}".format(d_spec['RoleName'])
    manage_group_policy(
        args, log, group, auth_account, policy_name, policy_doc, group_policies
    )
    managed_policies.append(policy_name)

    # handle excluded accounts
    if 'ExcludeAccounts' in d_spec and d_spec['ExcludeAccounts'] is not None:
        resource = build_resource_list(
            log, deployed['accounts'], d_spec, auth_spec, d_spec['ExcludeAccounts']
        )
        policy_doc = assemble_assume_role_policy_document(resource, 'Deny')
        policy_name = "DenyAssumeRole-{}".format(d_spec['RoleName'])
        manage_group_policy(
            args, log, group, auth_account, policy_name, policy_doc, group_policies
        )
        managed_policies.append(policy_name)

    # purge any policies for this role that are no longer being managed
    for policy_name in group_policies:
        delete_obsolete_group_policy(args, log, group, auth_account, policy_name, managed_policies)


def manage_local_user_in_accounts(account, args, log, auth_spec, deployed, accounts, lu_spec):
    """
    Create and manage a local user in an account per user specification.
    """

    account_name = account['Name']
    log.debug('account: %s, local user: %s' % (account_name, lu_spec['Name']))

    tags = [
        {'Key': 'contact_email', 'Value': lu_spec['ContactEmail']}
    ]

    # RequestId is not required
    if 'RequestId' in lu_spec and lu_spec['RequestId']:
        tags += [{'Key': 'request_id', 'Value': lu_spec['RequestId']}]

    path_spec = "/{}/service/{}/".format(auth_spec['default_path'], lu_spec['Service'])
    credentials = get_assume_role_credentials(account['Id'], args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        return
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)

    # get iam user object.
    user = iam_resource.User(lu_spec['Name'])
    try:
        user.load()
    except user.meta.client.exceptions.NoSuchEntityException:
        user_exists = False
    else:
        user_exists = True
        log.debug('account: %s, local user exists: %s' % (account_name, user.arn))
    # check for unmanaged user in account
    if user_exists:
        if not user.path.startswith('/' + auth_spec['default_path']):
            log.error("Can not manage local user '%s' in account '%s'. Unmanaged user with the same name already exists: %s" % (user.name, account_name, user.arn))
            return

    # check if local user should not exist
    if account_name not in accounts or orgtool.utils.ensure_absent(lu_spec):
        if user_exists:
            log.info("Deleting local user '%s' from account '%s'" % (user.name, account_name))
            if args['--exec']:
                delete_user(user, iam_client)
        return

    # update user tags
    if user_exists and user.tags != tags:
        log.info("Updating tags for user '%s'" % lu_spec['Name'])
        if args['--exec']:
            update_user_tags(iam_client, user, tags)

    # create local user and attach policies
    if not user_exists:
        log.info("Creating local user '%s' in account '%s'" % (lu_spec['Name'], account_name))
        if args['--exec']:
            user.create(Path=path_spec, Tags=tags)
            if 'Policies' in lu_spec and lu_spec['Policies']:
                user.load()
                for policy_name in lu_spec['Policies']:
                    policy_arn = get_policy_arn(iam_client, policy_name)
                    if policy_arn is None:
                        policy_arn = manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec)
                    log.info("Attaching policy '%s' to local user '%s' in account '%s'" % (policy_name, user.name, account_name))
                    if args['--exec'] and policy_arn:
                        user.attach_policy(PolicyArn=policy_arn)
    else:
        # validate path
        if user.path != path_spec:
            log.info("Updating path for local user '%s'" % user.arn)
            if args['--exec']:
                # hack around bug in boto3
                try:
                    user.update(NewPath=path_spec)
                except AttributeError as e:
                    log.debug('boto3 error when calling user.update(): %s' % e)

        # manage policy attachments
        attached_policies = [p.policy_name for p in list(user.attached_policies.all())]
        for policy_name in lu_spec['Policies']:
            if policy_name not in attached_policies:
                policy_arn = get_policy_arn(iam_client, policy_name)
                if policy_arn is None:
                    policy_arn = manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec)
                log.info("Attaching policy '%s' to local user '%s' in account '%s'" % (policy_name, user.name, account_name))
                if args['--exec'] and policy_arn:
                    user.attach_policy(PolicyArn=policy_arn)
            elif orgtool.utils.lookup(auth_spec['custom_policies'], 'PolicyName', policy_name):
                manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec)
        # datach obsolete policies
        for policy_name in attached_policies:
            if policy_name not in lu_spec['Policies']:
                policy_arn = get_policy_arn(iam_client, policy_name)
                log.info("Detaching policy '%s' from local user '%s' in account '%s'" % (policy_name, user.name, account_name))
                if args['--exec'] and policy_arn:
                    user.detach_policy(PolicyArn=policy_arn)


def manage_local_users(lu_spec, args, log, deployed, auth_spec):
    """
    Create and manage local IAM users in specified accounts and
    attach policies to users based on local_user specifications.
    """
    log.debug('considering %s' % lu_spec['Name'])
    # munge accounts list
    if lu_spec['Account'] == 'ALL':
        accounts = [a['Name'] for a in deployed['accounts']]
        if 'ExcludeAccounts' in lu_spec and lu_spec['ExcludeAccounts']:
            accounts = [a for a in accounts if a not in lu_spec['ExcludeAccounts']]
    else:
        accounts = lu_spec['Account']
    for account_name in accounts:
        if not orgtool.utils.lookup(deployed['accounts'], 'Name', account_name):
            log.error("Can not manage local user '%s' in account '%s'.  Account '%s' not found in Organization" % (lu_spec['Name'], account_name, account_name))
            accounts.remove(account_name)
    # run manage_local_user_in_accounts() task in thread pool
    queue_threads(log, deployed['accounts'], manage_local_user_in_accounts, f_args=(args, log, auth_spec, deployed, accounts, lu_spec))


def get_policies_from_spec(log, auth_spec, d_spec):
    """
    Return a list of policy names from either 'Policies' or 'PolicySet'
    attributes of d_spec.
    """
    if 'Policies' in d_spec:
        return d_spec.get('Policies')
    log.debug("Using PolicySet {} for role {}".format(d_spec['PolicySet'], d_spec['RoleName']))
    policy_set = orgtool.utils.lookup(auth_spec['policy_sets'], 'Name', d_spec['PolicySet'])
    if policy_set is None:
        log.error("policy set '{}' not found for role '{}'".format(d_spec['PolicySet'], d_spec['RoleName']))
        return list()
    else:
        return policy_set['Policies']


def get_tags_from_policy_set(auth_spec, d_spec):
    if 'PolicySet' in d_spec:
        return orgtool.utils.lookup(auth_spec['policy_sets'], 'Name', d_spec['PolicySet'], 'Tags')
    return None


def update_role_tags(args, log, iam_client, account_name, role, tags):
    '''
    Compare existing role tags to what is in spec and adjust as needed
    '''
    log.debug("role: '{}', account: '{}', role tags: {}; spec tags: {}".format(role.name, account_name, role.tags, tags))
    if tags is not None and role.tags != tags:
        log.info("Updating tags in role '{}' in account '{}'".format(role.name, account_name))
        if args['--exec']:
            if role.tags is not None:
                iam_client.untag_role(RoleName=role.role_name, TagKeys=[tag['Key'] for tag in role.tags])
            if tags is not None:
                iam_client.tag_role(RoleName=role.role_name, Tags=tags)


def create_role(args, log, role, iam_client, d_spec, account_name, path_spec, tags, policy_doc):
    log.info("Creating role '{}' in account '{}'".format(d_spec['RoleName'], account_name))
    if args['--exec']:
        create_role_attributes = dict(
            Description=d_spec['Description'],
            Path=path_spec,
            RoleName=d_spec['RoleName'],
            MaxSessionDuration=d_spec['Duration'],
            AssumeRolePolicyDocument=json.dumps(policy_doc),
        )
        if tags is not None:
            create_role_attributes['Tags'] = tags
        iam_client.create_role(**create_role_attributes)
        role.load()
        return role


def delete_role(args, log, role, account_name):
    log.info("Deleting role '{}' from account '{}'".format(role.role_name, account_name))
    if args['--exec']:
        for p in list(role.attached_policies.all()):
            role.detach_policy(PolicyArn=p.arn)
        role.delete()


def update_role_path(args, log, role, iam_client, account_name, d_spec, path_spec, tags, policy_doc):
    if role.path != path_spec:
        log.info("Updating path for role '{}' in account '{}'".format(
            role.role_name,
            account_name,
        ))
        if args['--exec']:
            delete_role(args, log, role, account_name)
            create_role(args, log, role, iam_client, d_spec, account_name, path_spec, tags, policy_doc)


def update_role_policy_document(args, log, role, iam_client, account_name, policy_doc):
    if role.assume_role_policy_document != policy_doc:
        log.info("Updating policy document in role '{}' in account '{}':\n{}".format(
            role.role_name,
            account_name,
            string_differ(
                yamlfmt(role.assume_role_policy_document),
                yamlfmt(policy_doc)
            )
        ))
        if args['--exec']:
            iam_client.update_assume_role_policy(
                RoleName=role.role_name,
                PolicyDocument=json.dumps(policy_doc)
            )


def update_role_description(args, log, role, iam_client, account_name, role_description):
    if role.description != role_description:
        log.info("Updating description in role '{}' in account '{}'".format(
            role.role_name,
            account_name
        ))
        if args['--exec']:
            iam_client.update_role_description(
                RoleName=role.role_name,
                Description=role_description
            )


def update_role_duration(args, log, role, iam_client, account_name, role_duration):
    if role.max_session_duration != role_duration:
        log.info("Updating max session duration in role '{}' in account '{}'".format(
            role.role_name,
            account_name
        ))
        if args['--exec']:
            iam_client.update_role(
                RoleName=role.role_name,
                MaxSessionDuration=role_duration
            )


def manage_attached_role_policies(args, log, role, iam_client, policy_list, account_name, auth_spec):
    attached_policies = [p.policy_name for p in list(role.attached_policies.all())]
    # attach missing policies
    for policy_name in policy_list:
        if policy_name not in attached_policies:
            policy_arn = get_policy_arn(iam_client, policy_name)
            if policy_arn is None:
                policy_arn = manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec)
            log.info("Attaching policy '{}' to role '{}' in account '{}'".format(
                policy_name,
                role.name,
                account_name
            ))
            if args['--exec'] and policy_arn:
                role.attach_policy(PolicyArn=policy_arn)
        elif 'custom_policies' in auth_spec and auth_spec['custom_policies'] and orgtool.utils.lookup(auth_spec['custom_policies'], 'PolicyName', policy_name):
            manage_custom_policy(iam_client, account_name, policy_name, args, log, auth_spec)
    # datach obsolete policies
    for policy_name in attached_policies:
        if policy_name not in policy_list:
            policy_arn = get_policy_arn(iam_client, policy_name)
            log.info("Detaching policy '{}' from role '{}' in account '{}'".format(
                policy_name,
                role.name,
                account_name
            ))
            if args['--exec'] and policy_arn:
                role.detach_policy(PolicyArn=policy_arn)


def get_assume_role_policy_document(d_spec, deployed, auth_spec):
    if 'TrustedAccount' in d_spec and d_spec['TrustedAccount']:
        trusted_account = orgtool.utils.lookup(deployed['accounts'], 'Name', d_spec['TrustedAccount'], 'Id')
    else:
        trusted_account = auth_spec['auth_account_id']
    principal = "arn:aws:iam::%s:root" % trusted_account
    statement = dict(Effect='Allow', Principal=dict(AWS=principal), Action='sts:AssumeRole')
    mfa = True
    if 'RequireMFA' in d_spec and d_spec['RequireMFA'] is False:
        mfa = False
    if mfa:
        statement['Condition'] = {'Bool': {'aws:MultiFactorAuthPresent': 'true'}}
    return dict(Version='2012-10-17', Statement=[statement])


def manage_delegation_role(account, args, log, auth_spec, deployed, trusting_accounts, d_spec):
    """
    Create and manage a cross account access delegetion role in an
    account based on delegetion specification.
    """
    account_name = account['Name']
    policy_list = get_policies_from_spec(log, auth_spec, d_spec)
    log.debug('account: {}, role: {}, policies: {}'.format(
        account_name,
        d_spec['RoleName'],
        policy_list,
    ))
    path_spec = orgtool.utils.munge_path(auth_spec['default_path'], d_spec)
    tags = get_tags_from_policy_set(auth_spec, d_spec)
    if 'Duration' not in d_spec:
        d_spec['Duration'] = 3600
    policy_doc = get_assume_role_policy_document(d_spec, deployed, auth_spec)
    credentials = get_assume_role_credentials(account['Id'], args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        return
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)
    role = iam_resource.Role(d_spec['RoleName'])
    if account_name not in trusting_accounts or orgtool.utils.ensure_absent(d_spec):
        try:
            role.load()
            delete_role(args, log, role, account_name)
            return
        except role.meta.client.exceptions.NoSuchEntityException:
            return
    try:
        role.load()
        update_role_tags(args, log, iam_client, account_name, role, tags)
        update_role_policy_document(args, log, role, iam_client, account_name, policy_doc)
        update_role_description(args, log, role, iam_client, account_name, d_spec['Description'])
        update_role_duration(args, log, role, iam_client, account_name, d_spec['Duration'])
        update_role_path(args, log, role, iam_client, account_name, d_spec, path_spec, tags, policy_doc)
        if role is not None:
            manage_attached_role_policies(args, log, role, iam_client, policy_list, account_name, auth_spec)
    except role.meta.client.exceptions.NoSuchEntityException:
        role = create_role(args, log, role, iam_client, d_spec, account_name, path_spec, tags, policy_doc)
        if role is not None:
            manage_attached_role_policies(args, log, role, iam_client, policy_list, account_name, auth_spec)
    return


def manage_delegations(d_spec, args, log, deployed, auth_spec):
    """
    Create and manage cross account access delegations based on
    delegation specifications.  Manages delegation roles in
    trusting accounts and group policies in Auth (trusted) account.
    """
    log.debug('considering %s' % d_spec['RoleName'])
    if d_spec['RoleName'] == args['--org-access-role']:
        log.error("Refusing to manage delegation '%s'" % d_spec['RoleName'])
        return

    # munge trusting_accounts list
    if d_spec['TrustingAccount'] == 'ALL':
        trusting_accounts = [a['Name'] for a in deployed['accounts']]
        if 'ExcludeAccounts' in d_spec and d_spec['ExcludeAccounts']:
            trusting_accounts = [a for a in trusting_accounts if a not in d_spec['ExcludeAccounts']]
    else:
        trusting_accounts = d_spec['TrustingAccount']
    for account_name in trusting_accounts:
        if not orgtool.utils.lookup(deployed['accounts'], 'Name', account_name):
            log.error("Can not manage delegation role '%s' in account '%s'.  Account '%s' not found in Organization" % (d_spec['RoleName'], account_name, account_name))
            trusting_accounts.remove(account_name)

    # is this a service role or a user role?
    if 'TrustedGroup' in d_spec and 'TrustedAccount' in d_spec:
        log.error("can not declare both 'TrustedGroup' or 'TrustedAccount' in delegation spec for role '%s'" % d_spec['RoleName'])
        return
    elif 'TrustedGroup' not in d_spec and 'TrustedAccount' not in d_spec:
        log.error("neither 'TrustedGroup' or 'TrustedAccount' declared in delegation spec for role '%s'" % d_spec['RoleName'])
        return
    elif 'TrustedAccount' in d_spec and d_spec['TrustedAccount']:
        # this is a service role. skip setting group policy
        pass
    else:
        # this is a user role. set group policies in Auth account
        set_group_assume_role_policies(args, log, deployed, auth_spec, d_spec)

    # run manage_delegation_role() task in thread pool
    queue_threads(log, deployed['accounts'], manage_delegation_role, f_args=(args, log, auth_spec, deployed, trusting_accounts, d_spec))


def main():
    args = docopt(__doc__, version=orgtool.__version__)
    core(args)


def core(args):
    log = get_logger(args)
    log.debug("%s: args:\n%s" % (__name__, args))
    log.info("Laurent Delhomme <delhom@amazon.com> AWS June 2020")
    args = load_config(log, args)
    auth_spec = validate_spec(log, args)

    org_credentials = get_assume_role_credentials(args['--master-account-id'], args['--org-access-role'])
    if isinstance(org_credentials, RuntimeError):
        log.critical(org_credentials)
        sys.exit(1)
    org_client = boto3.client('organizations', **org_credentials)
    validate_master_id(org_client, auth_spec)

    auth_credentials = get_assume_role_credentials(args['--auth-account-id'], args['--org-access-role'])
    if isinstance(auth_credentials, RuntimeError):
        log.critical(auth_credentials)
        sys.exit(1)
    iam_client = boto3.client('iam', **auth_credentials)

    deployed_accounts = scan_deployed_accounts(log, org_client)
    validate_accounts_unique_in_org_deployed(log, deployed_accounts)

    deployed = dict(
        users=orgtool.utils.get_iam_objects(iam_client.list_users, 'Users'),
        groups=orgtool.utils.get_iam_objects(iam_client.list_groups, 'Groups'),
        accounts=[a for a in deployed_accounts if a['Status'] == 'ACTIVE']
    )

    if args['report']:
        if args['--account']:
            deployed['accounts'] = [orgtool.utils.lookup(
                deployed['accounts'], 'Name', args['--account']
            )]
        if args['--users']:
            report_maker(log, deployed['accounts'], args['--org-access-role'], user_group_report, "IAM Users and Groups in all Org Accounts:", verbose=args['--full'])
        if args['--roles']:
            report_maker(log, deployed['accounts'], args['--org-access-role'], role_report, "IAM Roles and Custom Policies in all Org Accounts:", verbose=args['--full'])
        if args['--credentials']:
            report_maker(log, deployed['accounts'], args['--org-access-role'], credentials_report, "IAM Credentials Report in all Org Accounts:")
        if not (args['--users'] or args['--credentials'] or args['--roles']):
            report_maker(log, deployed['accounts'], args['--org-access-role'], account_authorization_report, "IAM Account Authorization:", verbose=args['--full'])

    if args['users']:
        if args['--disable-expired']:
            expire_users(log, args, deployed, auth_spec, credentials=None)
        else:
            create_users(auth_credentials, args, log, deployed, auth_spec)
            create_groups(auth_credentials, args, log, deployed, auth_spec)
            manage_group_members(auth_credentials, args, log, deployed, auth_spec)
            manage_group_policies(auth_credentials, args, log, deployed, auth_spec)

    if args['delegations']:
        if 'delegations' in auth_spec and auth_spec['delegations']:
            queue_threads(log, auth_spec['delegations'], manage_delegations, f_args=(args, log, deployed, auth_spec))

    if args['local-users']:
        if 'local_users' in auth_spec and auth_spec['local_users']:
            queue_threads(log, auth_spec['local_users'], manage_local_users, f_args=(args, log, deployed, auth_spec))


if __name__ == "__main__":
    main()
