"""Utility functions used by the various orgtool modules"""

import io
import os
import sys
import re
import difflib
import threading

try:
    import queue
except ImportError:
    import Queue as queue

import boto3
from botocore.exceptions import ClientError

import ruamel.yaml
import logging


S3_BUCKET_PREFIX = "orgtool"
S3_OBJECT_KEY = "deployed_accounts.yaml"


def get_s3_bucket_name(prefix=S3_BUCKET_PREFIX):
    """
    Generate an s3 bucket name based on a name prefix and the aws account ig
    """
    sts_client = boto3.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    return "-".join([prefix, account_id])


def lookup(dlist, lkey, lvalue, rkey=None):
    """
    Use a known key:value pair to lookup a dictionary in a list of
    dictionaries.  Return the dictonary or None.  If rkey is provided,
    return the value referenced by rkey or None.  If more than one
    dict matches, raise an error.
    args:
        dlist:   lookup table -  a list of dictionaries
        lkey:    name of key to use as lookup criteria
        lvalue:  value to use as lookup criteria
        rkey:    (optional) name of key referencing a value to return
    """
    items = [d for d in dlist if lkey in d and d[lkey] == lvalue]
    if not items:
        return None
    if len(items) > 1:
        raise RuntimeError(
            "Data Error: lkey: {}, lvalue: {} - lookup matches multiple items in dlist".format(
                lkey, lvalue
            )
        )
    if rkey:
        if rkey in items[0]:
            return items[0][rkey]
        return None
    return items[0]


def search_spec(spec, search_key, recurse_key):
    """
    Recursively scans spec structure and returns a list of values
    keyed with 'search_key' or and empty list.  Assumes values
    are either list or str.
    """
    value = []
    if search_key in spec and spec[search_key]:
        if isinstance(spec[search_key], str):
            value.append(spec[search_key])
        else:
            value += spec[search_key]
    if recurse_key in spec and spec[recurse_key]:
        for child_spec in spec[recurse_key]:
            value += search_spec(child_spec, search_key, recurse_key)
    return sorted(value)


def flatten_OUs(org_spec, log, path=None):
    if not path:
        if 'organizational_units' in org_spec and len(org_spec['organizational_units']) == 1:
            if org_spec['organizational_units'][0]['Name'] == 'root':
                return flatten_OUs(org_spec['organizational_units'], log, '/')
            elif 'MountingOUPath' in org_spec['organizational_units'][0] and org_spec['organizational_units'][0]['MountingOUPath']:
                return flatten_OUs(org_spec['organizational_units'], log, org_spec['organizational_units'][0]['MountingOUPath'])
            else:
                log.error("'Name: root' or 'MountingOUPath: ...' not found in org_spec")
                sys.exit(-1)
        else:
            log.error("org_spec does not contain 'organizational_units'")
            sys.exit(-1)
    else:
        OUs = {}
        for ou in org_spec:
            # ou_path = os.path.join(path,ou['Name'])
            if (path == '/'):
                ou_path = path + ou['Name']
            else:
                ou_path = path + '/' + ou['Name']
            OUs[ou_path] = ou
            if "Child_OU" in ou and ou["Child_OU"]:
                OUs.update(flatten_OUs(ou["Child_OU"], log, ou_path))
        return OUs


def ensure_absent(spec):
    """
    test if an 'Ensure' key is set to absent in dictionary 'spec'
    """
    if "Ensure" in spec and spec["Ensure"] == "absent":
        return True
    return False


def munge_path(default_path, spec):
    """
    Return formated 'Path' attribute for use in iam client calls.
    Unless specified path is fully qualified (i.e. starts with '/'),
    prepend the 'default_path'.
    """
    if "Path" in spec and spec["Path"]:
        if spec["Path"][0] == "/":
            if spec["Path"][-1] != "/":
                return spec["Path"] + "/"
            return spec["Path"]
        return "/%s/%s/" % (default_path, spec["Path"])
    return "/%s/" % default_path


def get_logger(args):
    """
    Setup logging.basicConfig from args.
    Return logging.Logger object.
    """
    # log level
    log_level = logging.INFO
    if args["--debug"]:
        log_level = logging.DEBUG
    if args["--quiet"]:
        log_level = logging.CRITICAL
    # log format
    log_format = "%(name)s: %(levelname)-9s%(message)s"
    if args["report"]:
        log_format = "%(message)s"
    if args["--debug"] == 1:
        log_format = "%(name)s: %(levelname)-9s%(funcName)s():  %(message)s"
    if not args["--exec"] and not args["report"]:
        log_format = "[dryrun] %s" % log_format
    if not args["--debug"] == 2:
        logging.getLogger("botocore").propagate = False
        logging.getLogger("boto3").propagate = False
    logging.basicConfig(stream=sys.stdout, format=log_format, level=log_level)
    log = logging.getLogger(__name__)
    return log


def valid_account_id(log, account_id):
    """Validate account Id is a 12 digit string"""
    if not isinstance(account_id, str):
        log.error("supplied account id {} is not a string".format(account_id))
        return False
    id_re = re.compile(r"^\d{12}$")
    if not id_re.match(account_id):
        log.error(
            "supplied account id '{}' must be a 12 digit number".format(account_id)
        )
        return False
    return True


def get_root_id(org_client):
    """
    Query deployed AWS Organization for its Root ID.
    """
    roots = org_client.list_roots()["Roots"]
    if len(roots) > 1:
        raise RuntimeError("org_client.list_roots returned multiple roots.")
    return roots[0]["Id"]


def validate_master_id(org_client, spec):
    """
    Don't mangle the wrong org by accident
    """
    master_account_id = org_client.describe_organization()["Organization"][
        "MasterAccountId"
    ]
    if master_account_id != spec["master_account_id"]:
        errmsg = (
            "The Organization Master Account Id '%s' does not match the "
            "'master_account_id' set in the spec-file" % master_account_id
        )
        raise RuntimeError(errmsg)
    return


def queue_threads(log, sequence, func, f_args=(), thread_count=20):
    """generalized abstraction for running queued tasks in a thread pool"""

    def worker(*args):
        log.debug("%s: q.empty: %s" % (threading.current_thread().name, q.empty()))
        while not q.empty():
            log.debug("%s: task: %s" % (threading.current_thread().name, func))
            item = q.get()
            log.debug(
                "%s: processing item: %s" % (threading.current_thread().name, item)
            )
            func(item, *args)
            q.task_done()

    q = queue.Queue()
    for item in sequence:
        log.debug("queuing item: %s" % item)
        q.put(item)
    log.debug("queue length: %s" % q.qsize())
    for i in range(thread_count):
        t = threading.Thread(target=worker, args=f_args)
        t.setDaemon(True)
        t.start()
    q.join()


def get_assume_role_credentials(account_id, role_name, region_name=None):
    """
    Get temporary sts assume_role credentials for account.
    """
    role_arn = "arn:aws:iam::%s:role/%s" % (account_id, role_name)
    role_session_name = account_id + "-" + role_name.split("/")[-1]
    sts_client = boto3.client("sts")

    if account_id == sts_client.get_caller_identity()["Account"]:
        return dict(
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            region_name=None,
        )
    else:
        try:
            credentials = sts_client.assume_role(
                RoleArn=role_arn, RoleSessionName=role_session_name
            )["Credentials"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                errmsg = "cannot assume role %s in account %s" % (role_name, account_id)
                return RuntimeError(errmsg)
        return dict(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region_name,
        )


def scan_deployed_accounts(log, org_client):
    """
    Query AWS Organization for deployed accounts.
    Returns a list of dictionary.
    """
    log.debug("running")
    accounts = org_client.list_accounts()
    deployed_accounts = accounts["Accounts"]
    while "NextToken" in accounts and accounts["NextToken"]:
        accounts = org_client.list_accounts(NextToken=accounts["NextToken"])
        deployed_accounts += accounts["Accounts"]

    # # # only return accounts that have an 'Name' key
    # # return [d for d in deployed_accounts if "Name" in d]

    # returrn all accounts, no filter.
    # The check have to be more strict and done outside of this function
    return deployed_accounts


def scan_deployed_tags_for_resource(log, org_client, ressource_id):
    """
    Query AWS Organization for deployed tags for the ressource.
    Returns a list of dictionary.
    """
    log.debug("running")
    tags = org_client.list_tags_for_resource(ResourceId=ressource_id)
    deployed_tags = tags["Tags"]
    while "NextToken" in tags and tags["NextToken"]:
        tags = org_client.list_tags_for_resource(
            ResourceId=ressource_id, NextToken=tags["NextToken"]
        )
        deployed_tags += tags["Tags"]
    # only return accounts that have an 'Name' key
    tag_dict = {}
    for tag in deployed_tags:
        tag_dict[tag["Key"]] = tag["Value"]

    return tag_dict


def scan_created_accounts(log, org_client):
    """
    Query AWS Organization for accounts with creation status of 'SUCCEEDED'.
    Returns a list of dictionary.
    """
    log.debug("running")
    status = org_client.list_create_account_status(States=["SUCCEEDED"])
    created_accounts = status["CreateAccountStatuses"]
    while "NextToken" in status and status["NextToken"]:
        status = org_client.list_create_account_status(
            States=["SUCCEEDED"], NextToken=status["NextToken"]
        )
        created_accounts += status["CreateAccountStatuses"]
    return created_accounts


def get_account_aliases(log, deployed_accounts, role):
    """
    Return dict of {Id:Alias} for all deployed accounts.

    role::  name of IAM role to assume to query all deployed accounts.
    """
    # worker function for threading
    def get_account_alias(account, log, role, aliases):
        if account["Status"] == "ACTIVE":
            credentials = get_assume_role_credentials(account["Id"], role)
            if isinstance(credentials, RuntimeError):
                log.error(credentials)
                return
            iam_client = boto3.client("iam", **credentials)
            response = iam_client.list_account_aliases()["AccountAliases"]
            if response:
                aliases[account["Id"]] = response[0]

    # call workers
    aliases = {}
    queue_threads(
        log,
        deployed_accounts,
        get_account_alias,
        f_args=(log, role, aliases),
        thread_count=10,
    )
    log.debug(yamlfmt(aliases))
    return aliases


def merge_aliases(log, deployed_accounts, aliases):
    """
    Merge account aliases into deployed_accounts lookup table.
    """
    for account in deployed_accounts:
        account["Alias"] = aliases.get(account["Id"], "")
        log.debug(account)
    return deployed_accounts


def string_differ(string1, string2):
    """Returns the diff of 2 strings"""
    diff = difflib.ndiff(
        string1.splitlines(keepends=True),
        string2.splitlines(keepends=True),
    )
    return "".join(list(diff))


def yamlfmt(dict_obj):
    """Convert a dictionary object into a yaml formated string"""
    yaml = ruamel.yaml.YAML()
    with io.StringIO() as string_stream:
        yaml.dump(dict_obj, string_stream)
        to_string = string_stream.getvalue()
    return to_string

    # return yaml.dump(dict_obj, default_flow_style=False)


def yamlfmtfile(dict_obj, file):
    """Convert a dictionary object into a yaml formated file"""
    yaml = ruamel.yaml.YAML()
    with open(file, "w") as f:
        yaml.dump(dict_obj, f)


def dump_to_spec_config(args, log, org_spec, config_key, spec_dir_template=None):
    log.debug("dump yaml dict to file config")

    if config_key not in org_spec:
        log.error("'{}' not found in org_spec".format(config_key))
        sys.exit(-1)

    spec_dir = args["--spec-dir"]
    file_config_name = config_key + ".yaml"
    dest_file_config_path = os.path.join(spec_dir, file_config_name)
    if spec_dir_template:
        source_file_config_path = os.path.join(spec_dir_template, file_config_name)
    else:
        source_file_config_path = dest_file_config_path

    # if not os.path.isfile(dest_file_config_path):
    #   log.error("spec config file not found: {}".format(dest_file_config_path))
    #   sys.exit(1)

    if not os.path.isfile(source_file_config_path):
        log.error("spec config file not found: {}".format(source_file_config_path))
        sys.exit(1)

    yaml = ruamel.yaml.YAML()
    # relaod the config to replace by the dump (from the source, then could be a template)
    with open(source_file_config_path) as file_config:
        spec_config = yaml.load(file_config.read())

    # change the content of the loaded config by the new dict to dump
    spec_config[config_key] = org_spec[config_key]

    # log.debug the content
    log.debug("\r\n" + yamlfmt(spec_config))

    # update the config file if --exec
    if args["--exec"]:
        yamlfmtfile(spec_config, dest_file_config_path)
        log.debug('Yaml dict configuration {} dump into {} with success'.format(config_key, dest_file_config_path))


def overbar(string):
    """
    Returns string preceeded by an overbar of the same length:
    >>> print(overbar('blee'))
    ____
    blee
    """
    return "%s\n%s" % ("_" * len(string), string)


def report_maker(log, accounts, role, query_func, report_header=None, **qf_args):
    """
    Generate a report by running a arbitrary query function in each account.
    The query function must return a list of strings.
    """
    # Thread worker function to gather report for each account
    def make_account_report(account, report, role):
        messages = []
        messages.append(overbar("Account:    %s" % account["Name"]))
        credentials = get_assume_role_credentials(account["Id"], role)
        if isinstance(credentials, RuntimeError):
            messages.append(credentials)
        else:
            messages += query_func(credentials, **qf_args)
        report[account["Name"]] = messages

    # gather report data from accounts
    report = {}
    queue_threads(
        log, accounts, make_account_report, f_args=(report, role), thread_count=10
    )
    # process the reports
    if report_header:
        log.info("\n\n%s" % overbar(report_header))
    for account, messages in sorted(report.items()):
        for msg in messages:
            log.info(msg)


def get_iam_objects(iam_client_function, object_key, f_args=dict()):
    """
    users = get_iam_objects(iam_client.list_users, 'Users')
    """
    iam_objects = []
    response = iam_client_function(**f_args)
    iam_objects += response[object_key]
    if "IsTruncated" in response:
        while response["IsTruncated"]:
            response = iam_client_function(Marker=response["Marker"], **f_args)
            iam_objects += response[object_key]
    return iam_objects
