#!/usr/bin/env python
"""Manage AWS IAM user login profile.

Usage:
    orgtoolloginprofile USER    [--config FILE]
                                [--master-account-id ID]
                                [--auth-account-id ID]
                                [--org-access-role ROLE]
                                [--report]
                                [--new | --reset | --reenable]
                                [--no-email]
                                [--disable]
                                [--disable-expired]
                                [--opt-ttl HOURS]
                                [--password PASSWORD]
                                [-q] [-d|-dd]

Options:
  USER                      Name of IAM user.
  -h, --help                Show this help message and exit.
  -V, --version             Display version info and exit.
  --config FILE             AWS Org config file in yaml format.
  --master-account-id ID    AWS account Id of the Org master account.
  --auth-account-id ID      AWS account Id of the authentication account.
  --org-access-role ROLE    IAM role for traversing accounts in the Org.
  --report                  Print user login profile report.  this is the default
  --new                     Create new login profile.
  --reset                   Reset password for existing login profile.
  --no-email                Do not email user when (re)setting login profile.
  --disable                 Delete existing login profile, disable access keys.
  --disable-expired         Delete profile if one-time-password exceeds --opt-ttl.
  --reenable                Recreate login profile, reactivate access keys.
  --opt-ttl HOURS           One-time-password time to live in hours [default: 24].
  --password PASSWORD       Supply password, do not require user to reset.
  -q, --quiet               Repress log output.
  -d, --debug               Increase log level to 'DEBUG'.
  -dd                       Include botocore and boto3 logs in log stream.

"""


import os
import sys
# import yaml
# import logging
from string import Template
import datetime
import smtplib
import pkg_resources
from email.message import EmailMessage


import boto3
from botocore.exceptions import ClientError
from docopt import docopt
from passwordgenerator import pwgenerator


import orgtool
from orgtool.utils import lookup, get_logger, get_assume_role_credentials, scan_deployed_accounts, get_account_aliases, merge_aliases
from orgtool.spec import load_config, validate_spec


# Relative path within orgtool project to template file used by prep_email()
EMAIL_TEMPLATE = 'data/email_template'


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def get_user_name():
    """
    Returns the IAM user_name of the calling identidy (i.e. you)
    """
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Arn'].split('/')[-1]


def list_delegations(log, user, deployed_accounts):
    """
    Return list of assume role resource arns for user.  Obtain these by
    parsing in-line group policies for each group the user is a member of.

    the policies we care about match one of two patterns:
        AllowAssumeRole-<rolename>
        DenyAssumeRole-<rolename>

    we assemble a list of allowed role arns, then we remove any of the
    denied arns.

    if the account_id field of a AllowAssumeRole-<rolename> matches the
    glob ('*') char, we generate the list of allowed role arns - one for
    every 'ACTIVE' account.
    """
    # groups = list(user.groups.all())
    role_arns = []
    for group in user.groups.all():

        allow_policies = [
            p for p in list(group.policies.all())
            if p.policy_name.startswith('AllowAssumeRole')
        ]
        for allow_policy in allow_policies:
            allow_arns = allow_policy.policy_document['Statement'][0]['Resource']
            if isinstance(allow_arns, str) and '*' in allow_arns:
                head, sep, tail = allow_arns.partition('*')
                allow_arns = []
                for account in deployed_accounts:
                    if account['Status'] == 'ACTIVE':
                        allow_arns.append(head + account['Id'] + tail)
            role_arns += allow_arns

        deny_policies = [
            p for p in list(group.policies.all())
            if p.name.startswith('DenyAssumeRole')
        ]
        for deny_policy in deny_policies:
            deny_arns = deny_policy.policy_document['Statement'][0]['Resource']
            deny_account_ids = [arn.split(':')[4] for arn in deny_arns]
            for id in deny_account_ids:
                for arn in role_arns:
                    if id in arn:
                        role_arns.remove(arn)
    return role_arns


def format_delegation_table(delegation_arns, deployed_accounts):
    """Generate formatted list of delegation attributes as printable string"""
    template = "  {}    {}{}{}\n"
    delegation_string = template.format('Account Id  ', 'Alias', ' '*19, 'Role')
    for assume_role_arn in delegation_arns:
        account_id = assume_role_arn.split(':')[4]
        alias = lookup(deployed_accounts, 'Id', account_id, 'Alias')
        if alias is None:
            alias = str()
        spacer = (24 - len(alias)) * ' '
        delegation_string += template.format(account_id, alias, spacer, assume_role_arn.partition('role/')[2])
    return delegation_string


def user_report(log, deployed_accounts, user, login_profile):
    """Generate report of IAM user's login profile, password usage, and
    assume_role delegations for any groups user is member of.
    """
    spacer = '{:<24}{}'
    log.info('\n')
    log.info(spacer.format('User:', user.name))
    log.info(spacer.format('Arn:', user.arn))
    log.info(spacer.format('User Id:', user.user_id))
    log.info(spacer.format('User created:', user.create_date))
    if login_profile:
        log.info(spacer.format('Login profile created:', login_profile.create_date))
        log.info(spacer.format('Passwd reset required:', login_profile.password_reset_required))
        if login_profile.password_reset_required:
            log.info(spacer.format(
                'One-time-passwd age:',
                utcnow() - login_profile.create_date,
            ))
        else:
            log.info(spacer.format('Password last used:', user.password_last_used))
    else:
        log.info(spacer.format('User login profile:', login_profile))
    assume_role_arns = list_delegations(log, user, deployed_accounts)
    if assume_role_arns:
        log.info('Delegations:\n{}'.format(
            format_delegation_table(assume_role_arns, deployed_accounts)
        ))


def validate_user(user_name, credentials=None):
    """Return a valid IAM User object"""
    if credentials:
        iam = boto3.resource('iam', **credentials)
    else:
        iam = boto3.resource('iam')
    user = iam.User(user_name)
    try:
        user.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return
    return user


def validate_login_profile(user):
    """Return a valid IAM LoginProfile object"""
    login_profile = user.LoginProfile()
    try:
        login_profile.load()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return
    return login_profile


def munge_passwd(passwd=None):
    """Return new 'passwd' string and boolean 'require_reset'.
    If passwd provided, set 'require_reset' to False.
    """
    if passwd:
        require_reset = False
    else:
        passwd = pwgenerator.generate()
        require_reset = True
    return passwd, require_reset


def create_profile(log, user, passwd, require_reset):
    log.debug('creating login profile for user %s' % user.name)
    return user.create_login_profile(
        Password=passwd,
        PasswordResetRequired=require_reset,
    )


def reset_profile(log, user, login_profile, passwd, require_reset):
    """Reset IAM user passwd by deleting and recreating login profile.
    This ensures the password creation date gets reset when updating a password.
    """
    if login_profile:
        log.debug('resetting login profile for user %s' % user.name)
        login_profile.delete()
        return login_profile.create(
            Password=passwd,
            PasswordResetRequired=require_reset
        )
    else:
        log.error("user '%s' has no login profile" % user.name)
        sys.exit(1)


def delete_profile(log, user, login_profile):
    if login_profile:
        log.info('deleting login profile for user %s' % user.name)
        login_profile.delete()
    else:
        log.warn("user '%s' has no login profile" % user.name)


def set_access_key_status(log, user, enable=True):
    """Enable or disable an IAM user's access keys"""
    for key in user.access_keys.all():
        if enable and key.status == 'Inactive':
            log.info('enabling access key %s for user %s' % (key.access_key_id, user.name))
            key.activate()
        elif not enable and key.status == 'Active':
            log.info('disabling access key %s for user %s' % (key.access_key_id, user.name))
            key.deactivate()


def onetime_passwd_expired(log, user, login_profile, hours):
    """Test if initial one-time-only password is expired"""
    if login_profile and login_profile.password_reset_required:
        log.debug('now: %s' % utcnow().isoformat())
        log.debug('ttl: %s' % datetime.timedelta(hours=hours))
        log.debug('delta: %s' % (utcnow() - login_profile.create_date))
        return (utcnow() - login_profile.create_date) > datetime.timedelta(hours=hours)
    return False


def prep_email(log, aliases, deployed_accounts, user, passwd):
    """Generate email body from template"""
    log.debug("loading file: '%s'" % EMAIL_TEMPLATE)
    trusted_id = boto3.client('sts').get_caller_identity()['Account']
    if aliases:
        trusted_account = aliases[trusted_id]
    else:
        trusted_account = trusted_id
    assume_role_arns = list_delegations(log, user, deployed_accounts)
    log.debug('assume_role_arns: %s' % assume_role_arns)
    template = os.path.abspath(pkg_resources.resource_filename(__name__, EMAIL_TEMPLATE))
    mapping = dict(
        user_name=user.name,
        onetimepw=passwd,
        trusted_account=trusted_account,
        delegations=format_delegation_table(assume_role_arns, deployed_accounts),
    )
    with open(template) as tpl:
        return Template(tpl.read()).substitute(mapping)


def build_email_message(user, message_body, spec):
    msg = EmailMessage()
    msg.set_content(message_body)
    msg['Subject'] = 'login profile'
    msg['To'] = lookup(spec['users'], 'Name', user.name, 'Email')
    msg['From'] = spec['org_admin_email']
    return msg


def send_email(msg, smtp_server):
    s = smtplib.SMTP(smtp_server)
    s.send_message(msg)
    s.quit()


def handle_email(log, args, spec, aliases, deployed_accounts, user, passwd):
    message_body = prep_email(log, aliases, deployed_accounts, user, passwd)
    if args['--no-email']:
        print(message_body)
    else:
        msg = build_email_message(user, message_body, spec)
        send_email(msg, spec['default_smtp_server'])


def main():
    args = docopt(__doc__, version=orgtool.__version__)
    core(args)


def core(args):
    # HACK ALERT!
    # set '--exec' and 'report' args to make get_logger() happy
    args['--exec'] = True
    if not (args['--new']
            or args['--reset']
            or args['--disable']
            or args['--disable-expired']
            or args['--reenable']):
        args['report'] = True
    else:
        args['report'] = False
    log = get_logger(args)
    log.debug(args)
    log.info("Laurent Delhomme <delhom@amazon.com> AWS June 2020")
    log.debug("%s: args:\n%s" % (__name__, args))
    args = load_config(log, args)
    spec = validate_spec(log, args)

    user = validate_user(args['USER'])
    if not user:
        log.critical('no such user: %s' % args['USER'])
        sys.exit(1)
    login_profile = validate_login_profile(user)
    passwd, require_reset = munge_passwd(args['--password'])
    org_credentials = get_assume_role_credentials(
            args['--master-account-id'],
            args['--org-access-role'])
    if isinstance(org_credentials, RuntimeError):
        log.critical(org_credentials)
        sys.exit(1)
    org_client = boto3.client('organizations', **org_credentials)
    deployed_accounts = scan_deployed_accounts(log, org_client)
    aliases = get_account_aliases(log, deployed_accounts, args['--org-access-role'])
    deployed_accounts = merge_aliases(log, deployed_accounts, aliases)
    log.debug(aliases)

    if args['--new']:
        if not login_profile:
            login_profile = create_profile(log, user, passwd, require_reset)
            handle_email(log, args, spec, aliases, deployed_accounts, user, passwd)
        else:
            log.warn("login profile for user '%s' already exists" % user.name)
            user_report(log, deployed_accounts, user, login_profile)

    elif args['--reset']:
        login_profile = reset_profile(log, user, login_profile, passwd, require_reset)
        handle_email(log, args, spec, aliases, deployed_accounts, user, passwd)

    elif args['--disable']:
        delete_profile(log, user, login_profile)
        set_access_key_status(log, user, False)

    elif args['--disable-expired']:
        if onetime_passwd_expired(log, user, login_profile, int(args['--opt-ttl'])):
            delete_profile(log, user, login_profile)

    elif args['--reenable']:
        if not login_profile:
            login_profile = create_profile(log, user, passwd, require_reset)
            handle_email(log, args, spec, aliases, deployed_accounts, user, passwd)
        else:
            log.warn("login profile for user '%s' already exists" % user.name)
        set_access_key_status(log, user, True)

    else:
        user_report(log, deployed_accounts, user, login_profile)


if __name__ == "__main__":
    main()
