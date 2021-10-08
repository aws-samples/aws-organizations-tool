#!/usr/bin/env python
"""Configure recources in an AWS Organization description files.

Usage:
  orgtoolconfigure reverse-setup --template-dir <path> --output-dir <path> [--force] --master-account-id <id> --org-access-role <role> [--exec] [-q] [-d|-dd]
  orgtoolconfigure distributed-config create --template-config <path> --child-config <path> [--prefix <value>] --config <path> --ou-name <name> --ou-path <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure distributed-config delete --config <path> --ou-name <name> --ou-path <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure account create --config <path> --account-name <name> --email <email> --ou-path <path> [--alias <alias> --tag <key>=<value>...] [--exec] [-q] [-d|-dd]
  orgtoolconfigure account update --config <path> --account-name <name> --alias <alias> [--exec] [-q] [-d|-dd]
  orgtoolconfigure account tag (add|update|remove) --config <path> --account-name <name> --tag <key>=<value>... [--exec] [-q] [-d|-dd]
  orgtoolconfigure account move --config <path> --account-name <name> --ou-path <path> [--config-from <path>] [--exec] [-q] [-d|-dd]
  orgtoolconfigure delegation (delete|create --trusted-account <name> --account-name <name>... --description <decription> [--require-mfa] [--ensure-present | --ensure-absent] --policies <policy-name>...) --config <path> --role-name <name> [--exec] [-q] [-d|-dd]
  orgtoolconfigure delegation trusting (add|remove) --config <path>  --role-name <name> --account-name <name>... [--exec] [-q] [-d|-dd]
  orgtoolconfigure organization-unit (create|delete) --config <path> --ou-path <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure organization-unit scp (add|remove) --config <path> --ou-path <path> [--scp-name <name>...] [--exec] [-q] [-d|-dd]
  orgtoolconfigure organization-unit tag (add|update|remove) --config <path> --ou-path <path> --tag <key>=<value>... [--exec] [-q] [-d|-dd]
  orgtoolconfigure get-ou-list --output-file <path> --config <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure validate --config <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure report
  orgtoolconfigure (--help|--version)

Modes of operation:
  reverse-setup                      Generate configuration files from the current AWS Organization deployed
                                     - config.yaml, 
                                     - spec.d/account.yaml, 
                                     - spec.d/common.yaml, 
                                     - spec.d/organizational_units.yaml, 
                                     - spec.d/custom_policies
                                     - spec.d/sc_policies.yaml 
 
  distributed-config create          create a distributed config inclued in the parent config            
  distributed-config delete          delete a distributed config and client the parent config
  account create                     create account
  account update                     update account alias
  account tag (add|update|remove)    add, update or remove account tags
  account move                       move account, can be cross distributed configuration
  delegation (delete|create)         create or delete delegation
  delegation trusting (add|remove)   add or remove trusting accounts in delegation
  organization-unit (create|delete)  create or delete organization unit
  organization-unit scp (add|remove) add or remove service control policy(ies) to a specific OU
  get-ou-list                        Generate a text file with all OU path
  validate                           validate the configuration and recusively all distributed config included


Options:
  -h, --help                  Show this help message and exit.
  -V, --version               Display version info and exit.
  --config <path>             AWS Org config file in yaml format.
  --account-name <name>
  --email <email>
  --alias <alias>
  --tag <key>=<value>         list of account tags to be added in a strucuture of key=value
  --template-config <path>
  --parent-config <path>
  --child-config <path>
  --ou-path <path>
  --prefix <value>
  --config-from <path>
  --trusted-account <name> 
  --description <decription> 
  --require-mfa 
  --policies <policy-name>
  --role-name <name>
  --scp-name <name>
  --ou-name <name>
  --template-dir <path> 
  --output-dir <path>
  --output-file <path>
  --master-account-id <id> 
  --org-access-role <role>
  --force
  --exec                      Execute proposed changes to AWS Org.
  -q, --quiet                 Repress log output.
  -d, --debug                 Increase log level to 'DEBUG'.
  -dd                         Include botocore and boto3 logs in log stream.
  

"""

from botocore import args
import os
import shutil
import boto3
from email_validator import validate_email, EmailNotValidError
from docopt import docopt

import orgtool
import orgtool.orgs
import orgtool.utils
from orgtool.orgs import *
from orgtool.utils import *
from orgtool.spec import *
from orgtool.validator import file_validator, spec_validator



import sys

def reverse_setup(args, log):
    # awsconfigure reverse-setup --template-dir <path> --output-dir <path> [--force] --master-account-id <id> --org-access-role <role> [--exec] [-q] [-d|-dd]

    credentials = get_assume_role_credentials(args['--master-account-id'], args['--org-access-role'])
    if isinstance(credentials, RuntimeError):
        log.error(credentials)
        raise Exception(credentials)
        # sys.exit(1)

    if '--template-dir' in args and args['--template-dir']:
        template_dir = args['--template-dir']
        template_dir = os.path.expanduser(template_dir)
        if not os.path.isdir(template_dir):
            log.error("template_dir not found: {}".format(template_dir))
            raise Exception("template_dir not found: {}".format(template_dir))
            # sys.exit(1)

    else:
        log.error("--template-dir required!")
        raise Exception("--template-dir required!")
        # sys.exit(1)

    if '--output-dir' in args and args['--output-dir']:
        output_dir = args['--output-dir']
        output_dir = os.path.expanduser(output_dir)
        if os.path.isdir(output_dir):
            if '--force' in args and args['--force']:
                log.info("With '--force', then delete existing output directory '{}".format(output_dir))
                if args['--exec']:
                    shutil.rmtree(output_dir)
            else:
                log.error("Output directory '{}' exists and could be not empty. Refusing to overwrite. Use '--force' to force overwrite".format(output_dir))
                raise Exception("Output directory '{}' exists and could be not empty. Refusing to overwrite. Use '--force' to force overwrite".format(output_dir))
                # sys.exit(1)
        
    else:
        log.error("--output-dir required!")
        raise Exception("--output-dir required!")
        # sys.exit(1)

    org_client = boto3.client('organizations', **credentials)
    root_id = get_root_id(org_client)

    deployed = dict(
        policies = scan_deployed_policies(org_client),
        accounts = scan_deployed_accounts(log, org_client),
        ou = scan_deployed_ou(log, org_client, root_id))

    orgtool.orgs.validate_accounts_unique_in_org_deployed(log, deployed['accounts'])
    
    reverse_config = dict(
        organizational_units = reverse_ou(org_client, log, deployed, "/root", "FullAWSAccess"),
        sc_policies = reverse_policies(org_client, log, deployed),
        accounts = reverse_accounts(org_client, log, deployed, args['--org-access-role'])
    )
    
    validator = file_validator(log)
    config_keys = ['organizational_units','sc_policies','accounts']
    for key in config_keys:
        spec={}
        spec[key] = reverse_config[key]

        errors = 0
        spec, errors = validate_spec_dict(log, spec, validator, errors)
        if errors:
            log.critical("The organization configuration is not compliant with orgtool limitation for {}. Run in debug mode for details".format(key))
            sys.exit(1)





    if args['--exec']:
        shutil.copytree(template_dir, output_dir)

        spec_dir = os.path.join(output_dir, "spec.d")
        config_file = os.path.join(output_dir, "config.yaml")
        config_file_common = os.path.join(spec_dir, "common.yaml")

        f = open(config_file,"rt")
        fc = f.read()
        fc = fc.replace('--spec_dir--', "--/spec.d")
        fc = fc.replace('--org_access_role--', args['--org-access-role'])
        fc = fc.replace('000000000000', args['--master-account-id'])
        f.close()
        f = open(config_file,"wt")
        f.write(fc)
        f.close()

        f = open(config_file_common,"rt")
        fc = f.read()
        fc = fc.replace('000000000000', args['--master-account-id'])
        f.close()
        f = open(config_file_common,"wt")
        f.write(fc)
        f.close()

        for key in reverse_config:
            file_name = key + ".yaml"
            file_path = os.path.join(spec_dir, file_name)
            f=open(file_path, "a+")
            f.write ("\r\n")
            f.write(yamlfmt(reverse_config[key]))
            f.close()

    log.info("reverse_config loaded:")
    log.info("\r\n" + yamlfmt(reverse_config))
    if args['--exec']:
        log.info("orgtool reverse-setup executed with success. Files delivered in {}".format(output_dir))

    return

def distributed_config_create(args, log, org_spec):
    # awsconfigure distributed-config create --template-config <path> --child-config <path> [--prefix <value>] --config <path> --ou-name <name> --ou-path <path> [--exec] [-q] [-d|-dd]

    # --------------- ADD TO CHILD CONFIG
    child_args = {}
    child_args['--exec'] = args['--exec']
    child_args['--spec-dir'] = None
    child_args['--config'] = args['--template-config']

    child_args = load_config(log, child_args)
    child_args['--master-account-id'] = args['--master-account-id']
    child_args['--org-access-role'] = args['--org-access-role']
    child_args['--auth-account-id'] = args['--auth-account-id']

    child_org_spec = validate_spec(log, child_args, False)
    child_org_spec['master_account_id'] = org_spec['master_account_id']
    child_org_spec['auth_account_id'] = org_spec['master_account_id']
    
    if 'organizational_units' in child_org_spec and child_org_spec['organizational_units']:
        child_org_spec['organizational_units'][0]['Name'] = args['--ou-name']
        child_org_spec['organizational_units'][0]['MountingOUPath'] = args['--ou-path']
    else:
        child_root_ou = {}
        child_root_ou['Name'] = args['--ou-name']
        child_root_ou['MountingOUPath'] = args['--ou-path']
        child_org_spec['organizational_units'] = []
        child_org_spec['organizational_units'] += [child_root_ou]
    # --------------- ADD TO CHILD CONFIG
    

    # --------------- ADD TO PARENT CONFIG
    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        parent_ou = OUs[args['--ou-path']]
    else:
        log.error("'{}' not found in org_spec OUs".format(args['--ou-path']))
        raise Exception("'{}' not found in org_spec OUs".format(args['--ou-path']))
        # sys.exit(-1)

    ou = {}
    ou['Name'] = args['--ou-name']
    ou['IncludeConfigPath'] = args['--child-config']
    if args['--prefix']:
        ou['PrefixRequired'] = args['--prefix']

    if 'Child_OU' in parent_ou and parent_ou['Child_OU']:
        parent_ou['Child_OU'] += [ou]
    else:
        parent_ou['Child_OU'] = [ou]
    # --------------- ADD TO PARENT CONFIG


    # --------------- DUMP CONFIGs
    if args['--exec']:
        template_dir = os.path.split(args['--template-config'])[0]
        child_config_dir = os.path.split(args['--child-config'])[0]
        shutil.copytree(template_dir, child_config_dir)

        # copy config.yaml
        shutil.copyfile(args['--config'], args['--child-config'])

        child_args = {}
        child_args['--exec'] = args['--exec']
        child_args['--config'] = args['--child-config']
        child_args = load_config(log, child_args)

        # copy --/spec.d/common.yaml
        source_common_file = os.path.join(args['--spec-dir'], 'common.yaml')
        dest_common_file = os.path.join(child_args['--spec-dir'], 'common.yaml')
        shutil.copyfile(source_common_file, dest_common_file)
    
    # Dump into the child organizational units file
    dump_to_spec_config(child_args,log,child_org_spec,'organizational_units')
    # Dump into the parent organizational units file
    dump_to_spec_config(args,log,org_spec,'organizational_units')
    # --------------- DUMP CONFIGs

def distributed_config_delete(args, log, org_spec):
    # awsconfigure distributed-config delete --config <path> --ou-name <name> --ou-path <path> [--exec] [-q] [-d|-dd]

    child_ou_path = os.path.join(args['--ou-path'], args['--ou-name'])

    OUs = flatten_OUs(org_spec, log)
    if OUs[child_ou_path] and OUs[args['--ou-path']]:
        child_ou = OUs[child_ou_path]
        parent_ou = OUs[args['--ou-path']]
        
        child_config_path = child_ou['IncludeConfigPath']

        for index, ou in enumerate(parent_ou['Child_OU']):
            if parent_ou['Child_OU'][index]['Name'] == args['--ou-name']:
                parent_ou['Child_OU'].pop(index)
                
                if args['--exec']:
                    # ------- delete child config directory
                    shutil.rmtree(os.path.split(child_config_path)[0])
                
                # ------- dump update parent organizational_units config
                dump_to_spec_config(args,log,org_spec,'organizational_units')
                break
    else:
        log.error("'{}' not found in org_spec OUs".format(child_ou_path))
        raise Exception("'{}' not found in org_spec OUs".format(child_ou_path))
        # sys.exit(-1)

def account_create(args, log, org_spec):
    # awsconfigure account create --config <path> --account-name <name> --email <email> --ou-path <path> [--alias <alias> --tag <key>=<value>...] [--exec] [-q] [-d|-dd]
  
    account = {}
    account['Name'] = args['--account-name'][0]
    try:
        v = validate_email(args['--email'])  # validate and get info
        email = v["email"]  # replace with normalized form
        account['Email'] = args['--email']
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        log.error(str(e))
        raise Exception(str(e))
        # sys.exit(-1)

    if '--alias' in args and args['--alias']:
        account['Alias'] = args['--alias']
    if '--tag' in args and args['--tag']:
        account['Tags'] = {}
        for tag in args['--tag']:
            tab = str(tag).split('=')
            if len(tab) != 2:
                log.critical("'{}' not formated as key=value".format(tab))
                sys.exit(1)
            else:
                key = tab[0]
                value = tab[1]
                account['Tags'][key] = value

    if 'accounts' in org_spec and org_spec['accounts']:
        org_spec['accounts'] += [account]
    else:
        org_spec['accounts'] = [account]

    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        parent_ou = OUs[args['--ou-path']]
        if 'Accounts' in parent_ou and parent_ou['Accounts']:
            parent_ou['Accounts'] += [account['Name']]
        else:
            parent_ou['Accounts'] = [account['Name']]
    else:
        log.error("'{}' not found in org_spec OUs".format(args['--ou-path']))
        raise Exception("'{}' not found in org_spec OUs".format(args['--ou-path']))
        # sys.exit(-1)

    dump_to_spec_config(args, log, org_spec, 'organizational_units')
    dump_to_spec_config(args, log, org_spec, 'accounts')

def account_update(args, log, org_spec):
    # awsconfigure account update --config <path> --account-name <name> --alias <alias> [--exec] [-q] [-d|-dd]
    if len(args['--account-name']) != 1:
        log.error("provide 1 single account name")
        raise Exception("provide 1 single account name")
        # sys.exit(-1)

    if 'accounts' in org_spec and org_spec['accounts']:
        # and args['--account-name'] in org_spec['accounts']:
        account = [a for a in org_spec['accounts'] if a['Name'] == args['--account-name'][0]]
        if len(account) == 1:
            if len(args['--alias']) == 0:
                account[0].pop('Alias', None)
            else:
                account[0]['Alias'] = args['--alias']
            
            # dump the changes
            dump_to_spec_config(args, log, org_spec, 'accounts')    
    
        else:
            log.error("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            raise Exception("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            # sys.exit(-1)
    else:
        log.error("org_spec has no accounts")
        raise Exception("org_spec has no accounts")
        # sys.exit(-1)

def account_tag_add(args, log, org_spec):
    # awsconfigure account tag add --config <path> --account-name <name> --tag <key>=<value>... [--exec] [-q] [-d|-dd]
    if len(args['--account-name']) != 1:
        log.error("provide 1 single account name")
        raise Exception("provide 1 single account name")
        # sys.exit(-1)

    if 'accounts' in org_spec and org_spec['accounts']:
        accounts = [a for a in org_spec['accounts'] if a['Name'] == args['--account-name'][0]]
        if len(accounts) == 1:
            account = accounts[0]
            if '--tag' in args and args['--tag']:
                # tags = {}
                for tag in args['--tag']:
                    tab = str(tag).split('=')
                    if len(tab) != 2:
                        log.critical("'{}' not formated as key=value".format(tab))
                        sys.exit(1)
                    else:
                        key = tab[0]
                        value = tab[1]
                        if not ('Tags' in account and account['Tags']): account['Tags'] = {}
                        account['Tags'][key] = value
                
                # dump the changes
                dump_to_spec_config(args, log, org_spec, 'accounts')

        else:
            log.error("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            raise Exception("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            # sys.exit(-1)
    else:
        log.error("org_spec has no accounts")
        raise Exception("org_spec has no accounts")
        # sys.exit(-1)
    
    return

def account_tag_update(args, log, org_spec):
    # with add using the same key
    return

def account_tag_remove(args, log, org_spec):
    # awsconfigure account tag remove --config <path> --account-name <name> --tag <key>=<value>... [--exec] [-q] [-d|-dd]
    if len(args['--account-name']) != 1:
        log.error("provide 1 single account name")
        raise Exception("provide 1 single account name")
        # sys.exit(-1)

    if 'accounts' in org_spec and org_spec['accounts']:
        accounts = [a for a in org_spec['accounts'] if a['Name'] == args['--account-name'][0]]
        if len(accounts) == 1:
            account = accounts[0]
            if '--tag' in args and args['--tag']:
                # tags = {}
                for tag in args['--tag']:
                    tab = str(tag).split('=')
                    if len(tab) != 2:
                        log.critical("'{}' not formated as key=value".format(tab))
                        sys.exit(1)
                    else:
                        key = tab[0]
                        value = tab[1]
                        if 'Tags' in account and account['Tags']: 
                            account['Tags'].pop(key, None)
                            if len(account['Tags']) == 0: account.pop('Tags', None)                
                # dump the changes
                dump_to_spec_config(args, log, org_spec, 'accounts')

        else:
            log.error("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            raise Exception("'{}' not found in org_spec accounts".format(args['--account-name'][0]))
            # sys.exit(-1)
    else:
        log.error("org_spec has no accounts")
        raise Exception("org_spec has no accounts")
        # sys.exit(-1)

    
    return

def account_move(args, log, org_spec):
    # awsconfigure account move --config <path> --account-name <name> --ou-path <path> [--config-from <path>] [--exec] [-q] [-d|-dd]
    if len(args['--account-name']) != 1:
        log.error("provide 1 single account name")
        raise Exception("provide 1 single account name")
        # sys.exit(-1)

    from_args = {}
    if '--config-from' in args and args['--config-from']:
        # account move from a config to another
        # --------------- Load from CONFIG
        from_args['--exec'] = args['--exec']
        from_args['--config'] = args['--config-from']
        from_args = load_config(log, from_args)
        from_org_spec = validate_spec(log, from_args, False)
    else:
        from_org_spec = org_spec
        # args['--config-from'] = args['--config']

    found = False
    if 'accounts' in from_org_spec and from_org_spec['accounts']:
        # and len([a for a in from_org_spec['accounts'] if a['Name'] == args['--account-name'][0]]) == 1:            
        for i, index in enumerate(from_org_spec['accounts']):
            if from_org_spec['accounts'][i]['Name'] ==  args['--account-name'][0]:
                found = True
                account = from_org_spec['accounts'][i]
                from_OUs = flatten_OUs(from_org_spec, log)
                OUs = flatten_OUs(org_spec, log)

                # test if dest is ok
                if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
                    #search source
                    for from_ou_path in from_OUs:
                        from_ou = from_OUs[from_ou_path]

                        if 'Accounts' in from_ou and from_ou['Accounts']:
                            for ii, iindex in enumerate(from_ou['Accounts']):
                                if from_ou['Accounts'][ii] == args['--account-name'][0]:
                                    # Source OU found
                                    # add account to dest    
                                    if 'Accounts' in OUs[args['--ou-path']] and OUs[args['--ou-path']]['Accounts']:
                                        OUs[args['--ou-path']]['Accounts'] += args['--account-name']
                                    else: 
                                        OUs[args['--ou-path']]['Accounts'] = args['--account-name']

                                    # remove account from source
                                    from_ou['Accounts'].pop(ii)
                                    if len(from_ou['Accounts']) == 0: from_ou.pop('Accounts', None)
                                    
                                    # move account from/to org spec
                                    from_org_spec['accounts'].pop(i)
                                    if len(from_org_spec['accounts']) == 0: from_org_spec['accounts'] = None
                                    if 'accounts' in org_spec and org_spec['accounts']:
                                        org_spec['accounts'] += [account]
                                    else:
                                        org_spec['accounts'] = [account]

                                    # dump the config
                                    dump_to_spec_config(args, log, org_spec, 'organizational_units')
                                    dump_to_spec_config(args, log, org_spec, 'accounts')                                    
                                    if '--config' in from_args and from_args['--config']: 
                                        dump_to_spec_config(from_args, log, from_org_spec, 'organizational_units')
                                        dump_to_spec_config(from_args, log, from_org_spec, 'accounts')
                                        
                                    # if from_args: dump_to_spec_config(from_args, log, from_org_spec, 'organizational_units')
                                    # exit from the function
                                    return
                    
                    # if pass here, account not found in any OUs
                    log.error("'{}' not found in org_spec OUs".format(args['--account-name']))
                    raise Exception("'{}' not found in org_spec OUs".format(args['--account-name']))
                    # sys.exit(-1)

                else:
                    log.error("'{}' not found in org_spec".format(args['--ou-path']))
                    raise Exception("'{}' not found in org_spec".format(args['--ou-path']))
                    # sys.exit(-1)

    if not found:
        log.error("Account '{}' not found in the organisation's accounts".format(args['--account-name'][0]))
        raise Exception("Account '{}' not found in the organisation's accounts".format(args['--account-name'][0]))
        sys.exit(-1)

def delegation_create(args, log, org_spec):
    # awsconfigure delegation create --trusted-account <name> --account-name <name>... --description <decription> [--require-mfa] [--ensure-present --ensure-absent] --policies <policy-name>... --config <path> --role-name <name> [--exec] [-q] [-d|-dd]
    # - RoleName: ORGTOOL_Provisioning
    #   Ensure: present
    #   RequireMFA: False
    #   Description: Full access to all services
    #   TrustingAccount:
    #   - entity1_tools
    #   - entity2_tools
    #   TrustedAccount: test
    #   Policies:
    #   - AdministratorAccess 

    delegations = []
    # search for a delegation with the same name
    if 'delegations' in org_spec and org_spec['delegations']:
        delegations = [d for d in org_spec['delegations'] if d['RoleName']==args['--role-name']]    

    # assume by default this delegation doesn't exist yet
    delegation = {}
    if len(delegations) ==1:
        # the delegation exist and will be updated with the new values
        delegation = delegations[0]

    # the new/update delegation
    delegation['RoleName'] = args['--role-name']
    delegation['Description'] = args['--description']

    if not args['--ensure-present'] and not args['--ensure-absent']:
        delegation['Ensure'] = 'present'

    elif args['--ensure-present'] and args['--ensure-absent']:
        delegation['Ensure'] = 'present'

    elif args['--ensure-present'] and not args['--ensure-absent']:
        delegation['Ensure'] = 'present'

    elif not args['--ensure-present'] and args['--ensure-absent']:
        delegation['Ensure'] = 'absent'

    # if args['--ensure-present']: delegation['Ensure'] = 'present'
    # if args['--ensure-absent']: delegation['Ensure'] = 'absent'        
    delegation['RequireMFA'] = args['--require-mfa']
    delegation['TrustedAccount'] = args['--trusted-account']
    delegation['TrustingAccount'] = args['--account-name']
    delegation['Policies'] = args['--policies']

    if 'delegations' in org_spec and org_spec['delegations']:
        org_spec['delegations'] += [delegation]
    else:
        org_spec['delegations'] = [delegation]

    dump_to_spec_config(args, log, org_spec, 'delegations')
    return

def delegation_delete(args, log, org_spec):
    # awsconfigure delegation delete --config <path> --role-name <name> [--exec] [-q] [-d|-dd]
    found = False
    # search for a delegation with the same name
    if 'delegations' in org_spec and org_spec['delegations']:
        for i, index in enumerate(org_spec['delegations']):
            if org_spec['delegations'][i]['RoleName'] == args['--role-name']:
                found = True
                org_spec['delegations'].pop(i)
                if len(org_spec['delegations']) == 0: org_spec['delegations'] = None

                dump_to_spec_config(args, log, org_spec, 'delegations')
                return
    
    if not found:
        log.error("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        raise Exception("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        # sys.exit(-1)

def delegation_trusting_add(args, log, org_spec):
    # awsconfigure delegation trusting add --config <path>  --role-name <name> --account-name <name>... [--exec] [-q] [-d|-dd]
    found = False
    changed = False
    # search for a delegation with the same name
    if 'delegations' in org_spec and org_spec['delegations']:
        delegations = [d for d in org_spec['delegations'] if d['RoleName']==args['--role-name']]   
        if len(delegations) == 1:
            found = True
            delegation = delegations[0]
    
            if 'TrustingAccount' in delegation and delegation['TrustingAccount']:
                
                for i, index in enumerate(args['--account-name']):
                    if len([a for a in delegation['TrustingAccount'] if a == args['--account-name'][i]]) == 0:
                        delegation['TrustingAccount'] += [args['--account-name'][i]]
                        changed = True
                    else:
                        log.debug("Account '{}' is already in the trusting account list of '{}'".format(args['--account-name'][i], args['--role-name']))
                    
            else:
                delegation['TrustingAccount'] = args['--account-name']
                changed = True

            if changed: dump_to_spec_config(args, log, org_spec, 'delegations')
    
    if not found:
        log.error("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        raise Exception("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        # sys.exit(-1)

def delegation_trusting_remove(args, log, org_spec):
    # awsconfigure delegation trusting remove --config <path>  --role-name <name> --account-name <name>... [--exec] [-q] [-d|-dd]
    found = False
    changed = False
    # search for a delegation with the same name
    if 'delegations' in org_spec and org_spec['delegations']:
        delegations = [d for d in org_spec['delegations'] if d['RoleName']==args['--role-name']]   
        if len(delegations) == 1:
            found = True
            delegation = delegations[0]
    
            if 'TrustingAccount' in delegation and delegation['TrustingAccount']:
                
                for i, index in enumerate(args['--account-name']):
                    for ii, iindex in enumerate(delegation['TrustingAccount']):
                        if args['--account-name'][i] == delegation['TrustingAccount'][ii]:
                            delegation['TrustingAccount'].pop(ii)
                            changed = True    
                            break

                    if len(delegation['TrustingAccount']) == 0:
                        delegation['TrustingAccount'] = None
                        changed = True
                        break
            else:
                log.debug("Trusting account list of '{}' is empty".format(args['--role-name']))

            if changed: 
                dump_to_spec_config(args, log, org_spec, 'delegations')
            
    
    if not found:
        log.error("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        raise Exception("Delegation '{}' not found in the organisation's delegations '{}'".format(args['--role-name'], args['--config']))
        # sys.exit(-1)

def organization_unit_create(args, log, org_spec):
    # awsconfigure organization-unit create --config <path> --ou-path <path> [--exec] [-q] [-d|-dd]
    # awsconfigure organization-unit create --config organization/.orgtool/root/config.yaml --ou-path /root/test1/lolo [--exec] [-q] [-d|-dd]


    OUs = flatten_OUs(org_spec,log)
    # check the OU doesn't exist yet
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        log.error("OU '{}' already found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' already found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        # sys.exit(-1)
    else:
    
        # get parent path and OU name
        parent_path = os.path.split(args['--ou-path'])[0]
        ou_name = os.path.split(args['--ou-path'])[1]
        
        if parent_path in OUs and OUs[parent_path]:
            # Parent OU found
            ou = OUs[parent_path]
            child_ou = {}
            child_ou['Name'] = ou_name
            if 'Child_OU' in ou and ou['Child_OU']:
                ou['Child_OU'] += [child_ou]
            else:
                ou['Child_OU'] = [child_ou]

            dump_to_spec_config(args, log, org_spec, 'organizational_units')

        else:
            # Parent path not found        
            log.error("OU '{}' not found in the organisation '{}'".format(parent_path, args['--config']))
            raise Exception("OU '{}' not found in the organisation '{}'".format(parent_path, args['--config']))
            # sys.exit(-1)
    
def organization_unit_delete(args, log, org_spec):
    # awsconfigure organization-unit delete --config <path> --ou-path <path> [--exec] [-q] [-d|-dd]

    OUs = flatten_OUs(org_spec,log)
    # check the OU exists
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:

        # get parent path and OU name
        parent_path = os.path.split(args['--ou-path'])[0]
        ou_name = os.path.split(args['--ou-path'])[1]
    
        # Parent OU found
        ou = OUs[parent_path]
        for i, index in enumerate(ou['Child_OU']):
            if ou['Child_OU'][i]['Name'] == ou_name:
                ou['Child_OU'].pop(i)
                if len(ou['Child_OU']) == 0:
                    ou.pop('Child_OU', None)
                
                dump_to_spec_config(args, log, org_spec, 'organizational_units')
                break

    else:
        # Parent path not found        
        log.error("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        # sys.exit(-1)

def organization_unit_scp_add(args, log, org_spec):
    # awsconfigure organization-unit scp add --config <path> --ou-path <path> [--scp-name <name>...] [--exec] [-q] [-d|-dd]
    # awsconfigure organization-unit scp add --config organization/.orgtool/root/config.yaml --ou-path /root/test1/test2 --scp-name toto --scp-name titi
    changed = False
    # search for the OU
    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        ou = OUs[args['--ou-path']]
        if 'SC_Policies' in ou and ou['SC_Policies']:

            for i, index in enumerate(args['--scp-name']):
                if len([scp for scp in ou['SC_Policies'] if scp == args['--scp-name'][i]]) == 0:
                    ou['SC_Policies'] += [args['--scp-name'][i]]
                    changed = True
                else:
                    log.debug("SCP '{}' is already in the SC_Policies list of '{}'".format(args['--scp-name'][i], args['--ou-path']))

        else:
            ou['SC_Policies'] = args['--scp-name']
            changed = True
    
        if changed: dump_to_spec_config(args, log, org_spec, 'organizational_units')

    else:
        log.error("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        # sys.exit(-1)

def organization_unit_scp_remove(args, log, org_spec):
    # awsconfigure organization-unit scp remove --config <path> --ou-path <path> [--scp-name <name>...] [--exec] [-q] [-d|-dd]
    # awsconfigure organization-unit scp remove --config organization/.orgtool/root/config.yaml --ou-path /root/test1/test2 --scp-name toto --scp-name titi
    changed = False
    # search for the OU
    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        ou = OUs[args['--ou-path']]

        if 'SC_Policies' in ou and ou['SC_Policies']:
            for i, index in enumerate(args['--scp-name']):
                for ii, iindex in enumerate(ou['SC_Policies']):
                    if args['--scp-name'][i] == ou['SC_Policies'][ii]:
                        ou['SC_Policies'].pop(ii)
                        changed = True    
                        break

                if len(ou['SC_Policies']) == 0:
                    ou['SC_Policies'] = None
                    changed = True
                    break
        else:
            log.debug("SC_Policies list of '{}' is empty".format(args['--ou-path']))

        if changed: dump_to_spec_config(args, log, org_spec, 'organizational_units')

    else:
        log.error("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        # sys.exit(-1)

def validate(args, log):
    # awsconfigure validate --config <path> --recursive
    # awsconfigure validate --config organization/.orgtool/root/config.yaml
    args['organization'] = True
    orgtool.orgs.core(args)
    log.debug(args)
    return

def get_ou_list(args, log, org_spec):
    
    OUs = flatten_OUs(org_spec, log)
    output = None
    for OU in OUs:
        if output:
            output += "\r\n{}".format(OU)
        else:
            output = OU

    with open(args['--output-file'], "w") as f:
        f.write(output)



def organization_unit_tag_add(args, log, org_spec):
    # awsconfigure organization-unit tag add --config <path> --ou-path <path> --tag <key>=<value> [--exec] [-q] [-d|-dd]
    
    if len(args['--ou-path'].split()) != 1:
        log.error("Please, provide 1 single OU Path")
        raise Exception("Please, provide 1 single OU Path")
    
    changed = False

    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        ou = OUs[args['--ou-path']]

        if '--tag' in args and args['--tag']:
            for tag in args['--tag']:
                tab = str(tag).split('=')
                if len(tab) != 2:
                    log.critical("'{}' not formated as key=value".format(tab))
                    sys.exit(1)
                else:
                    key = tab[0]
                    value = tab[1]
                    if not ('Tags' in ou and ou['Tags']): ou['Tags'] = {}
                    log.debug('Setting Tag with key ' + key + ' with value ' + value + ' for OU ' + ou['Name'])
                    ou['Tags'][key] = value
                    changed = True
        else:
            log.error('No Tags specified.')
            raise Exception('No Tags specified.')
    else:
        log.error("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))

    if changed: dump_to_spec_config(args, log, org_spec, 'organizational_units')

def organization_unit_tag_remove(args, log, org_spec):
    # awsconfigure organization-unit tag remove --config <path> --ou-path <path> --tag <key>=<value> [--exec] [-q] [-d|-dd]
    
    if len(args['--ou-path'].split()) != 1:
        log.error("Please, provide 1 single OU Path")
        raise Exception("Please, provide 1 single OU Path")
    
    changed = False
    # search for the OU
    OUs = flatten_OUs(org_spec, log)
    if args['--ou-path'] in OUs and OUs[args['--ou-path']]:
        ou = OUs[args['--ou-path']]
        if '--tag' in args and args['--tag']:
            for tag in args['--tag']:
                tab = str(tag).split('=')
                if len(tab) != 2:
                    log.critical("'{}' not formated as key=value".format(tab))
                    sys.exit(1)
                else:
                    key = tab[0]
                    value = tab[1]
                    if 'Tags' in ou and ou['Tags']:
                        if key in ou['Tags']:
                            ou['Tags'].pop(key, None)
                            log.debug('Removing tag with key ' + key)
                            changed = True
                            if len(ou['Tags']) == 0: ou.pop('Tags', None)
                        else: 
                            log.debug('No tag with key ' + key + 'for OU ' + ou['Name'] + '. So doing nothing.')
                    else:
                        log.debug('Trying to remove Tag with key ' + key + ' for OU ' + ou['Name'] + ' but OU has no Tags set. So doing nothing.')


        if changed: dump_to_spec_config(args, log, org_spec, 'organizational_units')

    else:
        log.error("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        raise Exception("OU '{}' not found in the organisation '{}'".format(args['--ou-path'], args['--config']))
        # sys.exit(-1)


def main():
    args = docopt(__doc__, version=orgtool.__version__)
    core(args)

def core(args, log=None):
    if not log:
        log = get_logger(args)
    log.debug(args)
    log.info("New feature for IaC, CLI to manipulate the configuration - Laurent Delhomme <delhom@amazon.com> AWS June 2020")
    if args['reverse-setup']: 
        reverse_setup(args, log)
        log.info("reverse-setup done!")
        return

    args = load_config(log, args)
    
    if args['validate']:
        log.debug('validate')
        validate(args, log)
        log.info("validate done!")
        return

    org_spec = validate_spec(log, args, False)

    if args['distributed-config']:
        if args['create']:
            log.debug('distributed-config create')
            distributed_config_create(args, log, org_spec)
            log.info("distributed-config create done!")

        if args['delete']:
            log.debug('distributed-config delete')
            distributed_config_delete(args, log, org_spec)
            log.info("distributed-config delete done!")

    if args['delegation']:
        if args['create']:
            log.debug('delegation create')
            delegation_create(args, log, org_spec)
            log.info("delegation create done!")

        if args['delete']:
            log.debug('delegation delete')
            delegation_delete(args, log, org_spec)
            log.info("delegation delete done!")

        if args['trusting']:
            if args['add']:
                log.debug('delegation trusting add')
                delegation_trusting_add(args, log, org_spec)
                log.info("delegation trusting add done!")

            if args['remove']:
                log.debug('delegation trusting remove')
                delegation_trusting_remove(args, log, org_spec)
                log.info("delegation trusting remove done!")

    if args['organization-unit']:
        if args['create']:
            log.debug('organization-unit create')
            organization_unit_create(args, log, org_spec)
            log.info("organization-unit create done!")

        if args['delete']:
            log.debug('organization-unit delete')
            organization_unit_delete(args, log, org_spec)
            log.info("organization-unit delete done!")

        if args['scp']:
            if args['add']:
                log.debug('organization-unit scp add')
                organization_unit_scp_add(args, log, org_spec)
                log.info("organization-unit scp add done!")

            if args['remove']:
                log.debug('organization-unit scp remove')
                organization_unit_scp_remove(args, log, org_spec)
                log.info("organization-unit scp remove done!")

        if args['tag']:
            if args['add']:
                log.debug('organization-unit tag add')
                organization_unit_tag_add(args, log, org_spec)
                log.info("organization-unit tag add done!")

            if args['remove']:
                log.debug('organization-unit tag remove')
                organization_unit_tag_remove(args, log, org_spec)
                log.info("organization-unit tag remove done!")

            if args['update']:
                log.debug('account tag update')
                organization_unit_tag_add(args, log, org_spec)
                log.debug("account tag update done!")

    if args['account']:
        if args['create']:
            log.debug('account create')
            account_create(args, log, org_spec)
            log.info("account create done!")
    
        if args['update']:
            log.debug('account update')
            account_update(args, log, org_spec)
            log.info("account update done!")

        if args['tag']:
            if args['add']:
                log.debug('account tag add')
                account_tag_add(args, log, org_spec)
                log.info("account tag add done!")

            if args['update']:
                log.debug('account tag update')
                log.info("account tag update done!")

            if args['remove']:
                log.debug('account tag remove')
                account_tag_remove(args, log, org_spec)
                log.info("account tag remove done!")

        if args['move']:
            log.debug('account move')
            account_move(args, log, org_spec)
            log.info("account move done!")
    
    if args['get-ou-list']:
        log.debug('get-ou-list')
        get_ou_list(args, log, org_spec)
        log.info("File created!")


if __name__ == "__main__":
    main()