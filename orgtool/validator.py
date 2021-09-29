"""
Spec validator schema data

ISSUES:
    place regex rule on email addresses, domain name
"""
import yaml

from cerberus import Validator, schema_registry
from orgtool.utils import yamlfmt


# Schema for validating spec files.  Since spec is accumulated from multiple
# files, we do not place a 'require' rule on first level keys.  Individual spec
# files have only a subset of these.
#



SPEC_FILE_SCHEMA = """
minimum_version:
  type: string
master_account_id:
  type: string
auth_account_id:
  type: string
default_domain:
  type: string
default_email_pattern:
  type: string
  required: False
  nullable: True
default_sc_policy:
  type: string
default_ou:
  type: string
move_unmanaged_account:
  type: boolean
default_path:
  type: string
default_smtp_server:
  type: string
org_admin_email:
  type: string
organizational_units:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: organizational_unit
sc_policies:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: sc_policy
accounts:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: account
users:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: user
groups:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: group
delegations:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: delegation
local_users:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: local_user
custom_policies:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: custom_policy
policy_sets:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: policy_set
stacks:
  nullable: True
  required: False
  type: list
  schema:
    type: dict
    schema: stack

"""


# Schema for validating the fully accumulate spec object.  This is where we
# ensure all required keys are present.  But we do not need to check sub
# schema, as that is done during spec_file validation.
#
SPEC_SCHEMA = """
minimum_version:
  required: True
  type: string
master_account_id:
  required: True
  type: string
auth_account_id:
  required: True
  type: string
default_domain:
  required: True
  type: string
default_email_pattern:
  required: True
  type: string
  required: False
  nullable: True
default_sc_policy:
  required: True
  type: string
default_ou:
  required: True
  type: string
move_unmanaged_account:
  required: True
  type: boolean
default_path:
  required: True
  type: string
default_smtp_server:
  required: True
  type: string
org_admin_email:
  required: True
  type: string
organizational_units:
  required: True
  nullable: True
  type: list
sc_policies:
  required: True
  nullable: True
  type: list
accounts:
  required: True
  nullable: True
  type: list
users:
  required: False
  nullable: True
  type: list
groups:
  required: False
  nullable: True
  type: list
delegations:
  required: False
  nullable: True
  type: list
local_users:
  required: False
  nullable: True
  type: list
custom_policies:
  required: False
  nullable: True
  type: list
policy_sets:
  required: False
  nullable: True
  type: list
stacks:
  required: False
  nullable: True
  type: list
"""


ORGANIZATIONAL_UNIT_SCHEMA = """
Name:
  required: False
  nullable: True
  type: string
IncludeConfigPath:
  required: False
  nullable: True
  type: string
MountingOUPath:
  required: False
  nullable: True
  type: string
PrefixRequired:
  required: False
  nullable: True
  type: string
Accounts:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Child_OU:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: organizational_unit
SC_Policies:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Tags:
  required: False
  nullable: True
  type: dict
  allow_unknown:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

POLICY_SCHEMA = """
PolicyName:
  required: True
  type: string
Description:
  required: False
  type: string
Statement:
  required: True
  anyof:
  - type: string
  - type: list
    schema:
      type: dict
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

ACCOUNT_SCHEMA = """
Name:
  required: True
  type: string
Email:
  required: False
  type: string
Alias:
  required: False
  type: string
Tags:
  required: False
  nullable: True
  type: dict
  allow_unknown:
    type: string
"""

USER_SCHEMA = """
Name:
  required: True
  type: string
Email:
  required: True
  type: string
CN:
  required: True
  type: string
RequestId:
  required: False
  type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

GROUP_SCHEMA = """
Name:
  required: True
  type: string
Path:
  required: False
  type: string
  nullable: True
Members:
  required: False
  nullable: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeMembers:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Policies:
  required: False
  nullable: True
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

LOCAL_USER_SCHEMA = """
Name:
  required: True
  type: string
ContactEmail:
  required: True
  type: string
RequestId:
  required: False
  type: string
Description:
  required: False
  type: string
Service:
  required: True
  type: string
Account:
  required: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeAccounts:
  required: False
  type: list
  schema:
    type: string
Policies:
  required: False
  type: list
  schema:
    type: string
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

DELEGATION_SCHEMA = """
RoleName:
  required: True
  type: string
Description:
  required: False
  type: string
TrustingAccount:
  required: True
  anyof:
  - type: string
    allowed:  
    - ALL
  - type: list
    schema:
      type: string
ExcludeAccounts:
  required: False
  type: list
  schema:
    type: string
TrustedGroup:
  required: False
  type: string
TrustedAccount:
  required: False
  type: string
RequireMFA:
  required: False
  type: boolean
Policies:
  required: True
  type: list
  schema:
    type: string
  excludes: PolicySet
PolicySet:
  required: True
  type: string
  excludes: Policies
Path:
  required: False
  type: string
  nullable: True
Duration:
  required: False
  type: integer
  min: 3600
  max: 43200
Ensure:
  required: False
  type: string
  allowed:
  - present
  - absent
"""

POLICY_SET_SCHEMA = """
Name:
  required: True
  type: string
Description:
  required: False
  nullable: True
  type: string
Policies:
  required: True
  nullable: True
  type: list
  schema:
    type: string
Tags:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: tag
"""

TAG_SCHEMA = """
Key:
  required: True
  type: string
Value:
  required: False
  type: string
"""


STACK_SCHEMA = """
Name:
  required: True
  type: string
Template:
  required: True
  type: string
Package:
  type: boolean
Parameters:
  required: False
  nullable: True
  type: list
  schema:
    type: dict
    schema: parameter
"""

PARAMETER_SCHEMA = """
Key:
  required: True
  type: string
Value:
  required: False
  type: string
"""


def file_validator(log):
    schema_registry.add('organizational_unit', yaml.safe_load(ORGANIZATIONAL_UNIT_SCHEMA))
    schema_registry.add('sc_policy', yaml.safe_load(POLICY_SCHEMA))
    schema_registry.add('account', yaml.safe_load(ACCOUNT_SCHEMA))
    schema_registry.add('user', yaml.safe_load(USER_SCHEMA))
    schema_registry.add('group', yaml.safe_load(GROUP_SCHEMA))
    schema_registry.add('local_user', yaml.safe_load(LOCAL_USER_SCHEMA))
    schema_registry.add('delegation', yaml.safe_load(DELEGATION_SCHEMA))
    schema_registry.add('custom_policy', yaml.safe_load(POLICY_SCHEMA))
    schema_registry.add('policy_set', yaml.safe_load(POLICY_SET_SCHEMA))
    schema_registry.add('tag', yaml.safe_load(TAG_SCHEMA))

    schema_registry.add('stack', yaml.safe_load(STACK_SCHEMA))
    schema_registry.add('parameter', yaml.safe_load(PARAMETER_SCHEMA))


    log.debug("adding subschema to schema_registry: {}".format(
            schema_registry.all().keys()))
    vfile = Validator(yaml.safe_load(SPEC_FILE_SCHEMA))
    log.debug("file_validator_schema: {}".format(vfile.schema))
    return vfile


def spec_validator(log):
    vspec = Validator(yaml.safe_load(SPEC_SCHEMA))
    log.debug("spec_validator_schema: {}".format(vspec.schema))
    return vspec
