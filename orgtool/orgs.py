#!/usr/bin/env python
"""Manage recources in an AWS Organization and Organization Unit tree.

Usage:
  orgtool (report|organization) [--config FILE]
                                [--spec-dir PATH]
                                [--master-account-id ID]
                                [--auth-account-id ID]
                                [--org-access-role ROLE]
                                [--exec] [-q] [-d|-dd]


  orgtool (--help|--version)

Modes of operation:
  report         Display organization status report only.
  organization   Run AWS Org management tasks per specification.

Options:
  -h, --help                Show this help message and exit.
  -V, --version             Display version info and exit.
  --config FILE             AWS Org config file in yaml format.
  --spec-dir PATH           Location of AWS Org specification file directory.
  --master-account-id ID    AWS account Id of the Org master account.
  --auth-account-id ID      AWS account Id of the authentication account.
  --org-access-role ROLE    IAM role for traversing accounts in the Org.
  --exec                    Execute proposed changes to AWS Org.
  -q, --quiet               Repress log output.
  -d, --debug               Increase log level to 'DEBUG'.
  -dd                       Include botocore and boto3 logs in log stream.

"""


# import yaml
import json
import sys
import os
# import time
# import shutil


import boto3
from docopt import docopt

import orgtool
import orgtool.utils
from orgtool.utils import yamlfmt, scan_deployed_tags_for_resource, lookup, get_account_aliases, ensure_absent, string_differ, search_spec
from orgtool.utils import get_logger, get_assume_role_credentials, get_root_id, scan_deployed_accounts, validate_master_id, flatten_OUs
from orgtool.spec import load_config, validate_spec


# def validate_accounts_unique_in_org_spec(log, root_spec):
#     """
#     Make sure accounts are unique across org
#     """
#     # recursively build mapping of accounts to ou_names
#     def map_accounts(spec, account_map={}):
#         if 'Accounts' in spec and spec['Accounts']:
#             for account in spec['Accounts']:
#                 if account in account_map:
#                     account_map[account].append(spec['Name'])
#                 else:
#                     account_map[account] = [(spec['Name'])]
#         if 'Child_OU' in spec and spec['Child_OU']:
#             for child_spec in spec['Child_OU']:
#                 map_accounts(child_spec, account_map)
#         return account_map
#     # find accounts set to more than one OU
#     unique = True
#     for account, ou in list(map_accounts(root_spec).items()):
#         if len(ou) > 1:
#             log.error("Account '%s' set multiple time: %s" % (account, ou))
#             unique = False
#     if not unique:
#         log.critical("Invalid org_spec: Account name should be unique in the org definition.")
#         sys.exit(1)

def validate_accounts_unique_in_org_deployed(log, deployed_accounts):
    """
    Make sure accounts are unique across existing org
    """
    # check for deployed[accounts]
    duplicate = False
    duplicate_values = []
    for account in deployed_accounts:
        if account['Name'] not in duplicate_values:
            accounts = [a for a in deployed_accounts if a['Name'] == account['Name']]
            count = len(accounts)
            if count > 1:
                duplicate = True
                duplicate_values.append(account['Name'])
                account_ids = [sub['Id'] for sub in accounts]
                log.error("Invalide deployed org: Account name should be unique. Duplicate account name '%s' found for Ids %s." % (account['Name'], str(account_ids)))

    # # check for deployed[ou] ##--> to stay commented for now
    # accounts = []
    # for ou in deployed['ou']:
    #     if 'Accounts' in ou:
    #         for account_name in ou['Accounts']:
    #             accounts.append({'Name': account_name , 'Path': ou['Path']})
    #             count = len([a for a in accounts if a['Name'] == account_name])
    #             if count > 1:
    #                 duplicate = True
    #                 log.error("Invalide deployed org: Account name should be unique. Duplicate account name '%s' found" % (account_name))

    if duplicate:
        log.critical("Invalide deployed org")
        log.critical("Duplicate account name found (%s). Org-Tool dosen't support multi account name in the same org." % (str(duplicate_values)))
        log.info("You could rename the account by following the AWS documentation at https://aws.amazon.com/premiumsupport/knowledge-center/change-organizations-name/")
        sys.exit(1)


def enable_policy_type_in_root(org_client, root_id):
    """
    Ensure policy type 'SERVICE_CONTROL_POLICY' is enabled in the
    organization root.
    """
    p_type = org_client.list_roots()['Roots'][0]['PolicyTypes']
    if (not p_type or (p_type[0]['Type'] == 'SERVICE_CONTROL_POLICY' and p_type[0]['Status'] != 'ENABLED')):
        org_client.enable_policy_type(RootId=root_id, PolicyType='SERVICE_CONTROL_POLICY')


def get_parent_id(org_client, account_id):
    """
    Query deployed AWS organanization for 'account_id. Return the 'Id' of
    the parent OrganizationalUnit or 'None'.
    """
    parents = org_client.list_parents(ChildId=account_id)['Parents']
    try:
        len(parents) == 1
        return parents[0]['Id']
    except Exception:
        raise RuntimeError("API Error: account '%s' has more than one parent: %s" % (account_id, parents))


def list_policies_in_ou(org_client, ou_id):
    """
    Query deployed AWS organanization.  Return a list (of type dict)
    of policies attached to OrganizationalUnit referenced by 'ou_id'.
    """
    policies_in_ou = org_client.list_policies_for_target(TargetId=ou_id, Filter='SERVICE_CONTROL_POLICY')['Policies']
    return sorted([ou['Name'] for ou in policies_in_ou])


def scan_deployed_policies(org_client):
    """
    Return list of Service Control Policies deployed in Organization
    """

    response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
    policies = response['Policies']

    while 'NextToken' in response and response['NextToken']:
        response = org_client.list_policies(Filter='SERVICE_CONTROL_POLICY', NextToken=response.get('NextToken'))
        policies += response['Policies']

    return policies


def build_deployed_ou_table(log, org_client, parent_name, parent_id, parent_path, deployed_ou):
    # recusive sub function to build the 'deployed_ou' table
    response = org_client.list_organizational_units_for_parent(ParentId=parent_id)
    child_ou = response['OrganizationalUnits']
    while 'NextToken' in response and response['NextToken']:
        response = org_client.list_organizational_units_for_parent(
            ParentId=parent_id, NextToken=response['NextToken'])
        child_ou += response['OrganizationalUnits']

    response = org_client.list_accounts_for_parent(ParentId=parent_id)
    accounts = response['Accounts']
    while 'NextToken' in response and response['NextToken']:
        response = org_client.list_accounts_for_parent(
            ParentId=parent_id, NextToken=response['NextToken'])
        accounts += response['Accounts']
    log.debug('parent_name: %s; ou: %s' % (parent_name, yamlfmt(child_ou)))
    log.debug('parent_name: %s; accounts: %s' % (parent_name, yamlfmt(accounts)))

    if not deployed_ou:
        deployed_ou.append(dict(
            Name=parent_name,
            Id=parent_id,
            Path=parent_path,
            Key=parent_id,
            Child_OU=[ou['Name'] for ou in child_ou if 'Name' in ou],
            Child_OU_Path=[(parent_path + '/' + ou['Name']) for ou in child_ou if 'Name' in ou],
            # Tags = org_client.list_tags_for_resource(ResourceId=parent_id)['Tags'],
            Accounts=[acc['Name'] for acc in accounts if 'Name' in acc]))
    else:
        for ou in deployed_ou:
            if ou['Path'] == parent_path:
                ou['Child_OU'] = [d['Name'] for d in child_ou]
                ou['Child_OU_Path'] = [(parent_path + '/' + d['Name']) for d in child_ou]
                ou['Accounts'] = [d['Name'] for d in accounts]
    for ou in child_ou:
        ou['ParentId'] = parent_id
        ou['Path'] = parent_path + '/' + ou['Name']
        ou['Key'] = parent_id + ':' + ou['Name']
        ou['Tags'] = org_client.list_tags_for_resource(ResourceId=ou['Id'])['Tags']
        deployed_ou.append(ou)
        build_deployed_ou_table(log, org_client, ou['Name'], ou['Id'], parent_path + '/' + ou['Name'], deployed_ou)


def scan_deployed_ou(log, org_client, root_id):
    """
    Recursively traverse deployed AWS Organization.  Return list of
    organizational unit dictionaries.
    """
    # build the table
    deployed_ou = []
    build_deployed_ou_table(log, org_client, 'root', root_id, '/root', deployed_ou)
    log.debug('\n' + yamlfmt(deployed_ou))
    return deployed_ou


def reverse_ou(org_client, log, deployed, ou_path, default_sc_policy):
    deployed_ou = lookup(deployed['ou'], 'Path', ou_path)
    revers = []
    ou = dict()
    ou["Name"] = deployed_ou["Name"]
    if "Accounts" in deployed_ou and len(deployed_ou["Accounts"]) > 0:
        ou["Accounts"] = deployed_ou["Accounts"]
    # if "Tags" in deployed_ou and len(deployed_ou["Tags"]) > 0: ou["Tags"] = deployed_ou["Tags"]
    tags = scan_deployed_tags_for_resource(log, org_client, deployed_ou["Id"])
    if len(tags) > 0:
        ou["Tags"] = tags
    if "Child_OU_Path" in deployed_ou and len(deployed_ou['Child_OU_Path']) > 0:
        ou["Child_OU"] = [reverse_ou(org_client, log, deployed, child_OU_Path, default_sc_policy)[0] for child_OU_Path in deployed_ou['Child_OU_Path']]
    policies = list_policies_in_ou(org_client, deployed_ou["Id"])
    # # ou["SC_Policies"] = policies
    if len(policies) > 1:
        policies.remove(default_sc_policy)
        ou["SC_Policies"] = policies
    revers.append(ou)
    return revers


def reverse_policies(org_client, log, deployed):
    policies = []
    for policy in deployed['policies']:
        policies.append(dict(
            PolicyName=policy['Name'],
            Description=policy['Description'],
            Statement=json.loads(org_client.describe_policy(PolicyId=policy['Id'])['Policy']['Content'])["Statement"]
        ))
    return policies


def reverse_accounts(org_client, log, deployed, org_access_role):
    aliases = get_account_aliases(log, deployed["accounts"], org_access_role)
    accounts = []
    for account in deployed["accounts"]:
        if account["Status"] == 'ACTIVE':
            item = dict()
            item["Name"] = account["Name"]
            item["Email"] = account["Email"]
            tags = scan_deployed_tags_for_resource(log, org_client, account["Id"])
            if len(tags) > 0:
                item["Tags"] = tags
            if account["Id"] in aliases and aliases[account["Id"]]:
                item["Alias"] = aliases[account["Id"]]
            accounts.append(item)
        else:
            log.info("Account %s (%s) is %s, then not added to the configuration" % (account["Name"], account["Id"], account["Status"]))
            pass

    return accounts


def display_provisioned_policies(org_client, log, deployed):
    """
    Print report of currently deployed Service Control Policies in
    AWS Organization.
    """
    header = "Provisioned Service Control Policies:"
    overbar = '_' * len(header)
    log.info("\n\n%s\n%s" % (overbar, header))
    for policy in deployed['policies']:
        log.info("\nName:\t\t%s" % policy['Name'])
        log.info("Description:\t%s" % policy['Description'])
        log.info("Id:\t%s" % policy['Id'])
        log.info("Content:")
        log.info(json.dumps(json.loads(org_client.describe_policy(
            PolicyId=policy['Id'])['Policy']['Content']),
            indent=2,
            separators=(',', ': ')))


def display_provisioned_ou(org_client, log, deployed_ou, parent_path, indent=0):
    """
    Recursive function to display the deployed AWS Organization structure.
    """
    # query aws for child orgs
    ou = lookup(deployed_ou, 'Path', parent_path)
    parent_id = lookup(deployed_ou, 'Path', parent_path, 'Id')
    child_ou_list = lookup(deployed_ou, 'Path', parent_path, 'Child_OU')
    child_accounts = lookup(deployed_ou, 'Path', parent_path, 'Accounts')
    # display parent ou name
    tab = '  '
    log.info(tab * indent + ou['Name'] + ' (' + ou['Path'] + '):')
    # look for policies
    policy_names = list_policies_in_ou(org_client, parent_id)
    if len(policy_names) > 0:
        log.info(tab * indent + tab + 'Policies: ' + ', '.join(policy_names))
    # look for accounts
    account_list = sorted(child_accounts)
    if len(account_list) > 0:
        log.info(tab * indent + tab + 'Accounts: ' + ', '.join(account_list))
    # look for child OUs
    if child_ou_list:
        log.info(tab * indent + tab + 'Child_OU:')
        indent += 2
        for ou_Name in child_ou_list:
            ou_path = parent_path + '/' + ou_Name
            # recurse
            display_provisioned_ou(org_client, log, deployed_ou, ou_path, indent)


def manage_account_moves(org_client, args, log, deployed, ou_spec, dest_parent_id, ou_spec_path):
    """
    Alter deployed AWS Organization.  Ensure accounts are contained
    by designated OrganizationalUnits based on OU specification.
    """
    if 'Accounts' in ou_spec and ou_spec['Accounts']:
        for account in ou_spec['Accounts']:
            account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
            if not account_id:
                log.warn("Account '%s' not yet in Organization" % account)
            else:
                source_parent_id = get_parent_id(org_client, account_id)
                if dest_parent_id != source_parent_id:
                    # log.info("Moving account '%s' to OU '%s'" % (account, ou_spec['Name']))
                    log.info("Moving account '%s' to OU '%s'" % (account, ou_spec_path))
                    if args['--exec']:
                        org_client.move_account(
                            AccountId=account_id,
                            SourceParentId=source_parent_id,
                            DestinationParentId=dest_parent_id)
                    # update deployed structure
                    dest = False
                    source = False
                    for i, item in enumerate(deployed['ou']):
                        if deployed['ou'][i]['Id'] == dest_parent_id:
                            # add the account to the dest deployed OU
                            deployed['ou'][i]['Accounts'] += [account]
                            dest = True
                        elif deployed['ou'][i]['Id'] == source_parent_id:
                            # remove account to the source deployed OU
                            for ii, iitem in enumerate(deployed['ou'][i]['Accounts']):
                                if deployed['ou'][i]['Accounts'][ii] == account:
                                    deployed['ou'][i]['Accounts'].pop(ii)
                                    source = True
                                    break
                        # dest and source are ok, then break
                        if dest and source:
                            break


def place_unmanged_accounts(org_client, args, log, deployed, account_list, dest_parent):
    """
    Move any unmanaged accounts into the default OU.
    """
    log.warn("move_unmanaged_account: True - New config to control if unmanaged account move to default OU")
    for account in account_list:
        account_id = lookup(deployed['accounts'], 'Name', account, 'Id')
        dest_parent_id = lookup(deployed['ou'], 'Name', dest_parent, 'Id')
        source_parent_id = get_parent_id(org_client, account_id)
        if dest_parent_id and dest_parent_id != source_parent_id:
            log.info("Moving unmanged account '%s' to default OU '%s'" % (account, dest_parent))
            if args['--exec']:
                org_client.move_account(
                    AccountId=account_id,
                    SourceParentId=source_parent_id,
                    DestinationParentId=dest_parent_id)


def manage_policies(org_client, args, log, deployed, org_spec, withdelete=True):
    """
    Manage Service Control Policies in the AWS Organization.  Make updates
    according to the sc_policies specification.  Do not touch
    the default policy.  Do not delete an attached policy.
    """
    for p_spec in org_spec['sc_policies']:
        policy_name = p_spec['PolicyName']
        log.debug("considering sc_policy: %s" % policy_name)
        # time.sleep(10) #pause due to throttling
        # dont touch default policy
        if policy_name == org_spec['default_sc_policy']:
            continue
        policy = lookup(deployed['policies'], 'Name', policy_name)
        # delete existing sc_policy
        if ensure_absent(p_spec) and withdelete:
            if policy:
                log.info("Deleting policy '%s'" % (policy_name))
                # dont delete attached policy
                if org_client.list_targets_for_policy(PolicyId=policy['Id'])['Targets']:
                    log.error("Cannot delete policy '%s'. Still attached to OU" % policy_name)
                elif args['--exec']:
                    org_client.delete_policy(PolicyId=policy['Id'])
            continue
        # create or update sc_policy
        policy_doc = json.dumps(dict(Version='2012-10-17', Statement=p_spec['Statement']))
        log.debug("spec sc_policy_doc: %s" % yamlfmt(policy_doc))
        # create new policy
        if not policy:
            log.info("Creating policy '%s'" % policy_name)
            if args['--exec']:
                response = org_client.create_policy(
                    Content=policy_doc,
                    Description=p_spec['Description'],
                    Name=p_spec['PolicyName'],
                    Type='SERVICE_CONTROL_POLICY')
                log.info("Creating policy '{}' response: {}".format(policy_name, response))
        # check for policy updates
        else:
            deployed_policy_doc = json.dumps(json.loads(org_client.describe_policy(PolicyId=policy['Id'])['Policy']['Content']))
            log.debug("real sc_policy_doc: %s" % yamlfmt(deployed_policy_doc))
            if (p_spec['Description'] != policy['Description'] or policy_doc != deployed_policy_doc):
                log.info("Updating policy '%s'" % policy_name)
                if args['--exec']:
                    response = org_client.update_policy(
                        PolicyId=policy['Id'],
                        Content=policy_doc,
                        Description=p_spec['Description'])
                    log.info("Update policy '{}' response: {}".format(policy_name, response))


def manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou_id, ou_spec_path):
    """
    Attach or detach specified Service Control Policy to a deployed
    OrganizatinalUnit.  Do not detach the default policy ever.
    """
    # create lists policies_to_attach and policies_to_detach
    if ou_id.startswith('dryrun-'):
        if 'SC_Policies' in ou_spec and isinstance(ou_spec['SC_Policies'], list):
            attached_policy_list = ou_spec['SC_Policies']
        else:
            attached_policy_list = []
    else:
        attached_policy_list = list_policies_in_ou(org_client, ou_id)

    if 'SC_Policies' in ou_spec and isinstance(ou_spec['SC_Policies'], list):
        spec_policy_list = ou_spec['SC_Policies']
    else:
        spec_policy_list = []
    policies_to_attach = [p for p in spec_policy_list if p not in attached_policy_list]
    policies_to_detach = [p for p in attached_policy_list if p not in spec_policy_list and p != org_spec['default_sc_policy']]
    # attach policies
    for policy_name in policies_to_attach:
        if not lookup(deployed['policies'], 'Name', policy_name):

            if args['--exec']:
                log.error("Error in config '{}', the policy '{}' can't be attached to the OU '{}' because the policy is not defined".format(args['--config'], policy_name, ou_spec['Path']))
                sys.exit(1)
                # raise RuntimeError("spec-file: ou_spec: policy '%s' not defined" % policy_name)
            else:
                log.warn("Error in config '{}', the policy '{}' couldn't be attached to the OU '{}' because the policy is not defined".format(args['--config'], policy_name, ou_spec['Path']))
        if not ensure_absent(ou_spec):
            log.info("Attaching policy '%s' to OU '%s'" % (policy_name, ou_spec_path))
            # log.info("Attaching policy '%s' to OU '%s'" % (policy_name, ou_spec['Name']))
            if args['--exec']:
                org_client.attach_policy(
                    PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                    TargetId=ou_id)
    # detach policies
    for policy_name in policies_to_detach:
        log.info("Detaching policy '%s' from OU '%s'" % (policy_name, ou_spec_path))
        # log.info("Detaching policy '%s' from OU '%s'" % (policy_name, ou_spec['Name']))
        if args['--exec']:
            org_client.detach_policy(
                PolicyId=lookup(deployed['policies'], 'Name', policy_name, 'Id'),
                TargetId=ou_id)


def manage_ou(org_client, args, log, deployed, org_spec, ou_spec_list, parent_name, parent_path):
    """
    Recursive function to manage OrganizationalUnits in the AWS
    Organization.
    """
    for ou_spec in ou_spec_list:
        ou_spec_path = parent_path + '/' + ou_spec['Name']
        ou_spec['Path'] = ou_spec_path
        # ou exists
        ou = lookup(deployed['ou'], 'Path', ou_spec_path)
        if ou:
            # check for child_ou. recurse before other tasks.
            if 'Child_OU' in ou_spec:
                manage_ou(
                    org_client,
                    args,
                    log,
                    deployed,
                    org_spec,
                    ou_spec['Child_OU'],
                    ou_spec['Name'],
                    ou_spec['Path'])

            # # manage attachment first if all are removed before deletion
            # manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou['Id'], ou_spec['Path'])
            # manage_account_moves(org_client, args, log, deployed, ou_spec, ou['Id'], ou_spec['Path'])

            # check if ou 'absent'
            if ensure_absent(ou_spec):
                log.info("Deleting OU %s" % ou_spec['Path'])
                # error if ou contains anything
                error_flag = False
                for key in ['Accounts', 'SC_Policies', 'Child_OU']:
                    # change to manage only Accouts and Child_OU
                    # for key in ['Accounts', 'Child_OU']:
                    if key in ou and ou[key]:
                        if key == 'SC_Policies':
                            log.error("Delete OU '%s'. Deployed '%s' will be unattach." % (ou_spec['Path'], key))
                            # remove SC_Policies before delettion
                            ou_spec.pop('SC_Policies', None)
                            manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou['Id'], ou_spec['Path'])
                        else:
                            log.error("Can not delete OU '%s'. Deployed '%s' exists." % (ou_spec['Path'], key))
                            error_flag = True
                if error_flag:
                    sys.exit(1)
                    continue
                else:
                    # remove the OU from deployed['ou'] to programaticaly allow recurscive delete
                    for i, item in enumerate(deployed['ou']):
                        if deployed['ou'][i]['Path'] == ou_spec['Path']:
                            # remove the OU
                            deployed['ou'].pop(i)
                            break

                    for i, item in enumerate(deployed['ou']):
                        if deployed['ou'][i]['Path'] == parent_path:
                            # remove the child_OU ref in the parent
                            for ii, iitem in enumerate(deployed['ou'][i]['Child_OU']):
                                if deployed['ou'][i]['Child_OU'][ii] == ou_spec['Name']:
                                    deployed['ou'][i]['Child_OU'].pop(ii)
                                    break
                            for iii, iiitem in enumerate(deployed['ou'][i]['Child_OU_Path']):
                                if deployed['ou'][i]['Child_OU_Path'][iii] == ou_spec['Path']:
                                    deployed['ou'][i]['Child_OU_Path'].pop(iii)
                                    break
                            break

                    if args['--exec']:
                        org_client.delete_organizational_unit(OrganizationalUnitId=ou['Id'])

            # manage account and sc_policy placement in OU
            else:
                manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, ou['Id'], ou_spec['Path'])
                manage_account_moves(org_client, args, log, deployed, ou_spec, ou['Id'], ou_spec['Path'])
                set_ou_tags(ou, log, args, ou_spec, org_client)
        # create new OU
        elif not ensure_absent(ou_spec):
            log.info("Creating new OU '%s' under parent '%s'" % (ou_spec['Path'], parent_name))

            parent_id = lookup(deployed['ou'], 'Path', parent_path, 'Id')
            name = ou_spec['Name']

            if args['--exec']:
                parent_id = lookup(deployed['ou'], 'Path', parent_path, 'Id')
                name = ou_spec['Name']
                new_ou = org_client.create_organizational_unit(ParentId=parent_id, Name=name)['OrganizationalUnit']

                # recursive if child OU
                # need to reload deployed['ou'] to make it work
                # root_id = get_root_id(org_client)
                # deployed['ou'] = scan_deployed_ou(log, org_client, root_id)
                new_OUs = []
                build_deployed_ou_table(log, org_client, name, new_ou['Id'], ou_spec_path, new_OUs)
                deployed['ou'] += new_OUs

            else:
                # if 'Accounts' in ou_spec and ou_spec['Accounts']:
                #     accounts = ou_spec['Accounts']
                # else:
                #     accounts = []

                # if 'SC_Policies' in ou_spec and ou_spec['SC_Policies']:
                #     scp = ou_spec['SC_Policies']
                # else:
                #     scp = []

                if 'Child_OU' in ou_spec and ou_spec['Child_OU']:
                    Child_OUs = [ou['Name'] for ou in ou_spec['Child_OU'] if 'Name' in ou]
                    Child_OUs_Path = [(parent_path + '/' + ou['Name']) for ou in ou_spec['Child_OU'] if 'Name' in ou]
                else:
                    Child_OUs = None
                    Child_OUs_Path = None

                new_ou = {}
                new_ou['Id'] = 'dryrun-' + ou_spec_path

                deployed['ou'].append(dict(
                    Name=name,
                    Id=new_ou['Id'],
                    Path=ou_spec_path,
                    Key=parent_id,
                    Child_OU=Child_OUs,
                    Child_OU_Path=Child_OUs_Path,
                    Accounts=[],
                    SC_Policies=[]))

            # account and sc_policy placement
            manage_policy_attachments(org_client, args, log, deployed, org_spec, ou_spec, new_ou['Id'], ou_spec['Path'])
            manage_account_moves(org_client, args, log, deployed, ou_spec, new_ou['Id'], ou_spec['Path'])
            set_ou_tags(new_ou, log, args, ou_spec, org_client)

            if ('Child_OU' in ou_spec and isinstance(new_ou, dict) and 'Id' in new_ou):
                manage_ou(
                    org_client,
                    args,
                    log,
                    deployed,
                    org_spec,
                    ou_spec['Child_OU'],
                    name,
                    ou_spec['Path'])


def transform_tag_spec_into_list_of_dict(tag_spec):
    if tag_spec is not None:
        return [{'Key': k, 'Value': v} for k, v in tag_spec.items()]
    return []


def sorted_tags(tag_list):
    sorted_tag_key_names = sorted([tag['Key'] for tag in tag_list])
    sorted_tags_ = []
    for tag_key_name in sorted_tag_key_names:
        sorted_tags_ += [tag for tag in tag_list if tag['Key'] == tag_key_name]
    return sorted_tags_


def update_ou_tags(org_client, ou, ou_tags, tag_spec, log):
    tagkeys = [tag['Key'] for tag in ou_tags]
    org_client.untag_resource(ResourceId=ou['Id'], TagKeys=tagkeys)
    if len(tag_spec) == 0:
        log.debug('No tags specified for OU ' + ou['Name'])
    else:
        org_client.tag_resource(
            ResourceId=ou['Id'],
            Tags=tag_spec,
        )


# def get_tag_spec_for_ou_path(ou_path, ou_spec, log):
# Recurive function to get tag_spec from yaml given an ou_path
#     tag_spec = {}

#     for ou in ou_spec:
#         if 'Child_OU' in ou:
#                 tag_spec = get_tag_spec_for_ou_path(
#                     ou_path,
#                     ou['Child_OU'],
#                     log)

#         if (len(tag_spec) > 0):
#             return tag_spec
#         if (len(tag_spec) == 0):
#             if 'Path' in ou:
#                 if ou['Path'] == ou_path:
#                     if 'Tags' in ou:
#                         tag_spec = ou['Tags']
#                         tag_spec = transform_tag_spec_into_list_of_dict(tag_spec)
#                         return tag_spec
#                     else:
#                         return tag_spec
#             #else:
#                 #log.warn('Path of organizational unit ' + ou['Name'] + ' could not be identified. This might cause empty tag specification.')
#     return tag_spec

def set_ou_tags(ou, log, args, ou_spec, org_client):

    if 'Tags' in ou_spec:
        tag_spec = ou_spec['Tags']
    else:
        tag_spec = {}
    tag_spec = transform_tag_spec_into_list_of_dict(tag_spec)

    # tag_spec = get_tag_spec_for_ou_path(ou['Path'], ou_spec['organizational_units'], log)
    ou_tags = {}
    if str(ou['Id']).startswith('dryrun-'):
        log.debug('In dryrun mode for a new OU, no need to get the existing tags')
    else:
        ou_tags = org_client.list_tags_for_resource(ResourceId=ou['Id'])['Tags']
    log.debug('tag_spec for OU "{}":\n{}'.format(
        ou_spec['Path'],
        yamlfmt(tag_spec),
    ))
    log.debug('ou_tags for OU "{}":\n{}'.format(
        ou_spec['Path'],
        yamlfmt(ou_tags),
    ))
    if sorted_tags(ou_tags) != sorted_tags(tag_spec):
        log.info("New feature for tagging OUs - Laurent Delhomme <delhom@amazon.com> AWS June 2020")
        log.info('Updating tags for OU "{}":\n{}'.format(
            ou_spec['Path'],
            string_differ(yamlfmt(ou_tags), yamlfmt(tag_spec)),
        ))
        if args['--exec']:
            update_ou_tags(org_client, ou, ou_tags, tag_spec, log)
    else:
        log.debug('Deployed tags == tag-spec. So doing nothing for OU "{}".'.format(
            ou_spec['Path']))


def main():
    args = docopt(__doc__, version=orgtool.__version__)
    core(args)


def core(args):
    log = get_logger(args)
    log.debug(args)
    log.info("Laurent Delhomme <delhom@amazon.com> AWS June 2020")

    args = load_config(log, args)
    credentials = get_assume_role_credentials(args['--master-account-id'], args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        sys.exit(1)
    org_client = boto3.client('organizations', **credentials)
    root_id = get_root_id(org_client)
    deployed = dict(
        policies=scan_deployed_policies(org_client),
        accounts=scan_deployed_accounts(log, org_client),
        ou=scan_deployed_ou(log, org_client, root_id))

    validate_accounts_unique_in_org_deployed(log, deployed['accounts'])

    if args['report']:
        log.info("To get files, use the command orgtoolconfigure reverse-setup --template-dir <path> --output-dir <path> [--force] --master-account-id <id> --org-access-role <role> [--exec] [-q] [-d|-dd]")
        log.info("The package provide a template for this purpose located into the folder 'spec_init_data.reverse'")
        log.info("The output files will contain the extract of OUs, SCPs and Accounts")
        log.info("Other resources (delegation, users, local_users ...) will not be updated by the exploration of the organization")

        header = 'Provisioned Organizational Units in Org:'
        overbar = '_' * len(header)
        log.info("\n%s\n%s" % (overbar, header))
        display_provisioned_ou(org_client, log, deployed['ou'], '/root')
        display_provisioned_policies(org_client, log, deployed)

    if args['organization']:
        org_spec = validate_spec(log, args)
        root_spec = lookup(org_spec['organizational_units'], 'Name', 'root')
        root_spec['Path'] = '/root'
        validate_master_id(org_client, org_spec)

        # validate_accounts_unique_in_org_spec(log, root_spec)

        managed = dict(
            accounts=search_spec(root_spec, 'Accounts', 'Child_OU'),
            # ou = search_spec(root_spec, 'Name', 'Child_OU'),
            ou=flatten_OUs(org_spec, log),
            policies=[p['PolicyName'] for p in org_spec['sc_policies']])

        # ensure default_sc_policy is considered 'managed'
        if org_spec['default_sc_policy'] not in managed['policies']:
            managed['policies'].append(org_spec['default_sc_policy'])
        enable_policy_type_in_root(org_client, root_id)
        manage_policies(org_client, args, log, deployed, org_spec, withdelete=False)

        # rescan deployed policies for added SCP
        deployed['policies'] = scan_deployed_policies(org_client)
        manage_ou(org_client, args, log, deployed, org_spec, org_spec['organizational_units'], 'root', '')
        # manage SCP again for policies detached and to be removed (Ensure: absent)
        manage_policies(org_client, args, log, deployed, org_spec, withdelete=True)

        # check for unmanaged resources
        for key in list(managed.keys()):
            if key == 'accounts':
                unmanaged = [a['Name'] for a in deployed[key] if a['Name'] not in managed[key]]
                if unmanaged:
                    log.warn("Unmanaged %s in Organization: %s" % (key, ', '.join(unmanaged)))
                    # # # Laurent Delhomme AWS - June 2020
                    if org_spec['move_unmanaged_account']:
                        # append unmanaged accounts to default_ou
                        place_unmanged_accounts(org_client, args, log, deployed, unmanaged, org_spec['default_ou'])
                    else:
                        log.info("Updated code, move_unmanaged_account set to False therefore unmanged account not moved to default OU - Laurent Delhomme <delhom@amazon.com> AWS June 2020")

            if key == 'policies':
                unmanaged = [a['Name'] for a in deployed[key] if a['Name'] not in managed[key]]
                if unmanaged:
                    log.warn("Unmanaged %s in Organization: %s" % (key, ', '.join(unmanaged)))

            if key == 'ou':
                unmanaged = [a for a in deployed[key] if a['Path'] not in managed[key]]
                unmanaged_path = [a['Path'] for a in deployed[key] if a['Path'] not in managed[key]]
                if unmanaged:
                    log.warn("Unmanaged %s in Organization: %s" % (key, ', '.join(unmanaged_path)))
                    # too protect for infinity while loop
                    protection = 0
                    protection_max = len(deployed['ou']) * 5

                    while len(unmanaged) != 0:
                        protection += 1
                        if protection > protection_max:
                            log.critical("Throw exception as a protection of the program. Too many loops to remove unmanaged OUs.")
                            sys.exit(1)
                            # if args['--exec']:
                            #
                            # else:
                            #     log.info("dryrun - then continu - not change will be applied")

                        for i, item in enumerate(unmanaged):
                            log.info("Deleting OU %s" % unmanaged[i]['Path'])

                            if 'Child_OU' in unmanaged[i] and len(unmanaged[i]['Child_OU']) != 0:
                                log.critical("Not able to delete OU %s because contains OU %s" % (unmanaged[i]['Path'], ', '.join(unmanaged[i]['Child_OU'])))

                            else:

                                if 'Accounts' in unmanaged[i] and len(unmanaged[i]['Accounts']) != 0:
                                    log.critical("Not able to delete OU %s because contains accounts %s" % (unmanaged[i]['Path'], ', '.join(unmanaged[i]['Accounts'])))
                                    log.critical("Move the account before deleting OU")
                                    if args['--exec']:
                                        log.critical("Then Exit in --exec mode")
                                        sys.exit(1)
                                    else:
                                        log.info("dryrun - then continu - not change will be applied")

                                # then delete the OU
                                if args['--exec']:
                                    org_client.delete_organizational_unit(OrganizationalUnitId=unmanaged[i]['Id'])
                                # update deployed structure
                                ou_path = unmanaged[i]['Path']
                                ou_name = unmanaged[i]['Name']
                                ou_parent_path = os.path.split(ou_path)[0]
                                unmanaged.pop(i)

                                for ii, iitem in enumerate(unmanaged):
                                    if unmanaged[ii]['Path'] == ou_parent_path:
                                        # remove the child_OU ref in the parent
                                        for iii, iiitem in enumerate(unmanaged[ii]['Child_OU']):
                                            if unmanaged[ii]['Child_OU'][iii] == ou_name:
                                                unmanaged[ii]['Child_OU'].pop(iii)
                                                break
                                        for iiii, iiiitem in enumerate(unmanaged[ii]['Child_OU_Path']):
                                            if unmanaged[ii]['Child_OU_Path'][iiii] == ou_path:
                                                unmanaged[ii]['Child_OU_Path'].pop(iiii)
                                                break
                                        break
                                break

        log.info("orgtool organization done!")


if __name__ == "__main__":
    main()
