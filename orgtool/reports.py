"""
Report maker utility and query functions

Todo:
    allow reporting on single account or short list of accounts
    substitute account alias for account id in reports
    
"""

import io
import csv
from orgtool.utils import *


# Report_maker utilities

def overbar(string):
    """
    Returns string preceeded by an overbar of the same length:
    >>> print(overbar('blee'))
    ____
    blee
    """
    return "%s\n%s" % ('_' * len(string), string)


def report_maker(log, accounts, role, query_func, report_header=None, **qf_args):
    """
    Generate a report by running a arbitrary query function in each account.
    The query function must return a list of strings.
    """
    # Thread worker function to gather report for each account
    def make_account_report(account, report, role):
        messages = []
        messages.append(overbar("Account:    %s" % account['Name']))
        credentials = get_assume_role_credentials(account['Id'], role)
        if isinstance(credentials, RuntimeError):
            messages.append(credentials)
        else:
            messages += query_func(credentials, **qf_args)
        report[account['Name']] = messages
    # gather report data from accounts
    report = {}
    queue_threads(
            log, accounts,
            make_account_report,
            f_args=(report, role),
            thread_count=10)
    # process the reports
    if report_header:
        log.info("\n\n%s" % overbar(report_header))
    for account, messages in sorted(report.items()):
        for msg in messages:
            log.info(msg)

    
# report_maker query functions

def user_group_report(credentials, verbose=False):
    """
    A report_maker query function.
    Reports IAM users and Groups in an account.

    ISSUE: report access keys, ssh keys, mfa devices, http users

    """
    messages = []
    iam_client = boto3.client('iam', **credentials)

    user_info = []
    users = get_iam_objects(iam_client.list_users, 'Users')
    for u in users:
        if verbose:
            user_info.append(u)
        else:
            user_info.append(u['Arn'])
    if user_info:
        messages.append(yamlfmt(dict(Users=user_info)))

    group_info = []
    groups = get_iam_objects(iam_client.list_groups, 'Groups')
    for g in groups:
        if verbose:
            group_info.append(g)
        else:
            group_info.append(g['Arn'])
    if group_info:
        messages.append(yamlfmt(dict(Groups=group_info)))
    #if groups:
    #    messages.append("Groups:")
    #    if verbose:
    #        messages.append(yamlfmt(groups))
    #    else:
    #        messages += ["  %s" % group['Arn'] for group in groups]
    return messages


def credentials_report(credentials):
    """
    A report_maker query function.
    IAM Credential report in an account

    ISSUES:
      Clean up exception handling:
      botocore.errorfactory.CredentialReportNotPresentException: An error occurred (ReportNotPresent) when calling the GetCredentialReport operation: Unknown
    """

    messages = []
    iam_client = boto3.client('iam', **credentials)
    try:
        response = iam_client.get_credential_report()
    except Exception as e:
        response = iam_client.generate_credential_report()
        messages.append(yamlfmt(response))
        return messages

    report_file_object = io.StringIO(response['Content'].decode())
    reader = csv.DictReader(report_file_object)
    user_info = []
    for row in reader:
        user = dict()
        for key in reader.fieldnames:
            user['UserName'] = row['user']
            user['Arn'] = row['arn']
            if (key not in ['user', 'arn'] and 
                    row[key] not in ['N/A', 'not_supported', 'no_information', 'false']):
                user[key] = row[key]
        user_info.append(user)

    if user_info:
        messages.append(yamlfmt(dict(Users=user_info)))
    return messages


def role_report(credentials, verbose=False):
    """
    A report_maker query function.
    Reports IAM custom policies and roles in an account.
    """
    messages = []
    iam_client = boto3.client('iam', **credentials)
    iam_resource = boto3.resource('iam', **credentials)

    policy_info = []
    custom_policies = get_iam_objects(iam_client.list_policies, 'Policies', 
            dict(Scope='Local'))
    for p in custom_policies:
        if verbose:
            policy_version_id = iam_resource.Policy(p['Arn']).default_version_id
            policy_info.append(dict(
                Arn=p['Arn'],
                Statement=iam_resource.PolicyVersion(
                    p['Arn'], 
                    policy_version_id
                ).document['Statement'],
            ))
        else:
            policy_info.append(p['Arn'])
    if policy_info:
        messages.append(yamlfmt(dict(CustomPolicies=policy_info)))

    role_info = []
    roles = get_iam_objects(iam_client.list_roles, 'Roles')
    for r in roles:
        role = iam_resource.Role(r['RoleName'])
        if verbose:
            role_info.append(dict(
                Arn=role.arn,
                Statement=role.assume_role_policy_document['Statement'],
                AttachedPolicies=[p.policy_name for p in list(role.attached_policies.all())],
            ))
        else:
            role_info.append(role.arn)
    if role_info:
        messages.append(yamlfmt(dict(Roles=role_info)))
    return messages


def account_authorization_report(credentials, verbose=False):
    """
    A report_maker query function.
    IAM Account Authorization Reporting

    """
    messages = []
    iam_client = boto3.client('iam', **credentials)

    user_info = []
    users = get_iam_objects(
            iam_client.get_account_authorization_details, 
            'UserDetailList',
            dict(Filter=['User']))
    for u in users:
        if verbose:
            user_info.append(u)
        else:
            user_info.append(u['Arn'])
    if user_info:
        messages.append(yamlfmt(dict(Users=user_info)))

    group_info = []
    groups = get_iam_objects(
            iam_client.get_account_authorization_details, 
            'GroupDetailList',
            dict(Filter=['Group']))
    for u in groups:
        if verbose:
            group_info.append(u)
        else:
            group_info.append(u['Arn'])
    if group_info:
        messages.append(yamlfmt(dict(Groups=group_info)))

    role_info = []
    roles = get_iam_objects(
            iam_client.get_account_authorization_details, 
            'RoleDetailList',
            dict(Filter=['Role']))
    for u in roles:
        if verbose:
            role_info.append(u)
        else:
            role_info.append(u['Arn'])
    if role_info:
        messages.append(yamlfmt(dict(Roles=role_info)))

    policy_info = []
    policies = get_iam_objects(
            iam_client.get_account_authorization_details, 
            'Policies',
            dict(Filter=['LocalManagedPolicy']))
    for u in policies:
        if verbose:
            policy_info.append(u)
        else:
            policy_info.append(u['Arn'])
    if policy_info:
        messages.append(yamlfmt(dict(CustomPolicies=policy_info)))


    return messages




# Obsolete resource display functions. For reference only
#
#display_provisioned_users(log, args, deployed, auth_spec, credentials)
#display_provisioned_groups(log, args, deployed, credentials)
#display_roles_in_accounts(log, args, deployed, auth_spec)


def display_provisioned_users(log, args, deployed, auth_spec, credentials):
    """
    Print report of currently deployed IAM users in Auth account.
    """
    header = "Provisioned IAM Users in Auth Account:"
    overbar = '_' * len(header)
    log.info("\n%s\n%s\n" % (overbar, header))
    if args['--full']:
        aliases = get_account_aliases(log, deployed['accounts'],
                args['--org-access-role'])
    for name in sorted([u['UserName'] for u in deployed['users']]):
        arn = lookup(deployed['users'], 'UserName', name, 'Arn')
        if args['--full']:
            user = validate_user(name, credentials)
            if user:
                login_profile = validate_login_profile(user)
                user_report(log, aliases, user, login_profile)
        else:
            spacer = ' ' * (12 - len(name))
            log.info("%s%s\t%s" % (name, spacer, arn))


def display_provisioned_groups(log, args, deployed, credentials):
    """
    Print report of currently deployed IAM groups in Auth account.
    List group memebers, attached policies and delegation assume role
    profiles.
    """
    # Thread worker function to assemble lines of a group report
    def display_group(group_name, report, iam_resource):
        log.debug('group_name: %s' % group_name)
        messages = []
        group = iam_resource.Group(group_name)
        members = list(group.users.all())
        attached_policies = list(group.attached_policies.all())
        assume_role_resources = [p.policy_document['Statement'][0]['Resource']
                for p in list(group.policies.all()) if
                p.policy_document['Statement'][0]['Action'] == 'sts:AssumeRole']
        overbar = '_' * (8 + len(group_name))
        messages.append('\n%s' % overbar)
        messages.append("%s\t%s" % ('Name:', group_name))
        messages.append("%s\t%s" % ('Arn:', group.arn))
        if members:
            messages.append("Members:")
            messages.append("\n".join(["  %s" % u.name for u in members]))
        if attached_policies:
            messages.append("Policies:")
            messages.append("\n".join(["  %s" % p.arn for p in attached_policies]))
        if assume_role_resources:
            messages.append("Assume role profiles:")
            messages.append("  Account\tRole ARN")
            profiles = {}
            for role_arn in assume_role_resources:
                account_name = lookup(deployed['accounts'], 'Id',
                        role_arn.split(':')[4], 'Name')
                if account_name:
                    profiles[account_name] = role_arn
            for account_name in sorted(profiles.keys()):
                messages.append("  %s:\t%s" % (account_name, profiles[account_name]))
        report[group_name] = messages

    group_names = sorted([g['GroupName'] for g in deployed['groups']])
    log.debug('group_names: %s' % group_names)
    header = "Provisioned IAM Groups in Auth Account:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))

    # log report
    if args['--full']:
        # gather report data from groups
        report = {}
        iam_resource = boto3.resource('iam', **credentials)
        queue_threads(log, group_names, display_group, f_args=(report, iam_resource),
                thread_count=10)
        for group_name, messages in sorted(report.items()):
            for msg in messages:
                log.info(msg)
    else:
        # just print the arns
        log.info('')
        for name in group_names:
            arn = lookup(deployed['groups'], 'GroupName', name, 'Arn')
            spacer = ' ' * (12 - len(name))
            log.info("%s%s\t%s" % (name, spacer, arn))


def display_roles_in_accounts(log, args, deployed, auth_spec):
    """
    Print report of currently deployed delegation roles in each account
    in the Organization.
    We only care about AWS principals, not Service principals.
    """
    # Thread worker function to gather report for each account
    def display_role(account, report, auth_spec):
        messages = []
        overbar = '_' * (16 + len(account['Name']))
        messages.append('\n%s' % overbar)
        messages.append("Account:\t%s" % account['Name'])
        credentials = get_assume_role_credentials(
                account['Id'],
                args['--org-access-role'])
        if isinstance(credentials, RuntimeError):
            messages.append(credentials)
        else:
            iam_client = boto3.client('iam', **credentials)
            iam_resource = boto3.resource('iam', **credentials)
            roles = [r for r in iam_client.list_roles()['Roles']]
            custom_policies = iam_client.list_policies(Scope='Local')['Policies']
            if custom_policies:
                messages.append("Custom Policies:")
                for policy in custom_policies:
                    messages.append("  %s" % policy['Arn'])
            messages.append("Roles:")
            for r in roles:
                role = iam_resource.Role(r['RoleName'])
                if not args['--full']:
                    messages.append("  %s" % role.arn)
                else:
                    principal = role.assume_role_policy_document['Statement'][0]['Principal']
                    if 'AWS' in principal:
                        messages.append("  %s" % role.name)
                        messages.append("    Arn:\t%s" % role.arn)
                        messages.append("    Principal:\t%s" % principal['AWS'])
                        attached = [p.policy_name for p
                                in list(role.attached_policies.all())]
                        if attached:
                            messages.append("    Attached Policies:")
                            for policy in attached:
                                messages.append("      %s" % policy)
        report[account['Name']] = messages

    # gather report data from accounts
    report = {}
    queue_threads(log, deployed['accounts'], display_role, f_args=(report, auth_spec),
            thread_count=10)
    # process the reports
    header = "Provisioned IAM Roles in all Org Accounts:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for account, messages in sorted(report.items()):
        for msg in messages:
            log.info(msg)
