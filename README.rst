Getting started with orgtool
=============================

A configuration management tool set for AWS Organizations.

NOTA:
This tool is a fork from aws-orgs, published by Ashley Gould <agould@ucop.edu> at https://github.com/ucopacme/aws-orgs


Features
--------

- Ensure state of AWS Organizations and IAM resourses per `yaml`_ formatted specification files.
- Configure AWS Organizations resources:

  - organizational units
  - service control policies
  - account creation and organizational unit placement

- Centrally manage IAM access across AWS Organization accounts:

  - IAM users/groups in a central *Auth* account
  - customer managed IAM policies
  - IAM roles and trust delegation in organization accounts

- New features:

  - Nested configurations : Manage the organization description with a combinaison of includes of distributed sub organization configuration
  - CLI to manipulate and change the configuration files
  - Generate configuration from an existing organisation
  - Support of resource tagging OUs and accounts.  




Installation
------------
Editable copy using virtual environment (recommended)::

  git clone https://gitlab.aws.dev/delhom/org-tool
  python -m venv ./org-tool/venv
  source ./org-tool/venv/bin/activate
  pip install -e ./org-tool/


Editable copy::

  git clone https://gitlab.aws.dev/delhom/org-tool
  pip install -e org-tool/


Uninstall::

  pip uninstall orgtool


Configuration quick start
-------------------------

Run the ``orgtool-spec-init`` script to generate an initial set of spec-files::

  orgtool-spec-init

This generates an initial ``config.yaml`` spec files under ``~/.orgtool``.  Edit
these as needed to suit your environment.

See ``--help`` option for full usage.



Console Scripts
---------------

``orgtool`` provides the following python executibles:  

orgtool
  Manage recources in an AWS Organization.

awsaccounts
  Manage accounts in an AWS Organization.

awsauth
  Manage users, group, and roles for cross account access in an 
  AWS Organization.

awsloginprofile
  Manage AWS IAM user login profile.


All commands execute in ``dry-run`` mode by default.  Include the ``--exec``
flag to affect change to AWS resources.  Run each of these with the '--help'
option for usage documentation.

::

  orgtool report
  orgtool organization
  orgtool organization --exec

  orgtoolaccounts report
  orgtoolaccounts create [--exec]
  orgtoolaccounts alias [--exec]

  orgtoolaccounts invite --account-id ID [--exec]
  # from invited account:
  orgtool-accessrole --master_id ID [--exec]

  orgtoolauth report
  orgtoolauth report --users
  orgtoolauth report --delegations
  orgtoolauth report --credentials --full
  orgtoolauth report --account ucpath-prod --users --full

  orgtoolauth users [--exec]
  orgtoolauth delegations [--exec]
  orgtoolauth local-users [--exec]

  orgtoolloginprofile maryanne
  orgtoolloginprofile maryanne --new
  orgtoolloginprofile maryanne --reset
  orgtoolloginprofile maryanne --disable-expired --opt-ttl 48

  orgtoolconfigure reverse-setup --template-dir <path> --output-dir <path> [--force] --master-account-id <id> --org-access-role <role> [--exec] [-q] [-d|-dd]
  orgtoolconfigure account tag (add|update|remove) --config <path> --account-name <name> --tag <key>=<value>... [--exec] [-q] [-d|-dd]
  orgtoolconfigure validate --config <path> [--exec] [-q] [-d|-dd]
  orgtoolconfigure report



:Author:
    Laurent Delhomme (delhom@amazon.com)

:Version: 0.9.1
