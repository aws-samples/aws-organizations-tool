# Getting started with orgtool

**orgtool** is a configuration management tool set for AWS Organizations written in python. This tooling enable the configuration and management of AWS Organization with code.

## Features

---

- Ensure state of AWS Organizations and IAM resources per `yaml`\_ formatted specification files.
- Configure AWS Organizations resources

  - organizational units
  - service control policies
  - account creation and organizational unit placement

- Centrally manage IAM access across AWS Organization accounts:

  - IAM users/groups in a central _Auth_ account
  - customer managed IAM policies
  - IAM roles and trust delegation in organization accounts

- New features:
  - Manage the organization with a combination of includes of distributed sub aws organization configuration
  - Generation of the configuration files from an existing AWS Organization
  - CLI to manipulate and change the configuration files of an AWS Organisation
  - Tagging of Organization Units

## Installation

---

### Editable copy using virtual environment (recommended):

    git clone https://gitlab.aws.dev/delhom/org-tool
    python -m venv ./org-tool/venv
    source ./org-tool/venv/bin/activate
    pip install -e ./org-tool/

### Editable copy

    git clone https://gitlab.aws.dev/delhom/org-tool
    pip install -e org-tool/

### Uninstall:

    pip uninstall orgtool

## Configuration quick start

Run the `orgtool-spec-init` script to generate an initial set of spec-files::

    orgtool-spec-init

This generates an initial `config.yaml` spec files under `~/.orgtool`. Edit
these as needed to suit your environment.

See `--help` option for full usage.

or

## Console Scripts

`orgtool` provides the following python executables:

- orgtool

  - Manage resources in an AWS Organization.

- orgtoolaccounts

  - Manage accounts in an AWS Organization.

- orgtoolauth

  - Manage users, group, and roles for cross account access in an AWS Organization.

- orgtoolloginprofile
  Manage AWS IAM user login profile.

- orgtoolconfigure
  - Manage reverse engineering of an existing organization
  - Provide CLI command to update the AWS Organization `yaml` description.
  - These CLI commands are used for organization management with code

All commands execute in `dry-run` mode, by default. Include the `--exec`
flag to affect change to AWS resources and orgtool configuration files.
Run each of these with the '--help' option for usage documentation.

    orgtool report
    orgtool organization
    orgtool organization --exec

    orgtoolaccounts report
    orgtoolaccounts create [--exec]

    orgtoolauth report
    orgtoolauth report --users
    orgtoolauth report --credentials --full
    orgtoolauth report --account ucpath-prod --users --full

    orgtoolauth users [--exec]
    orgtoolauth delegations [--exec]
    orgtoolauth local-users [--exec]

    orgtoolconfigure reverse-setup --template-dir ./spec_init_data.blank --output-dir ~/.orgtool/root [--force] --master-account-id 123456789012 --org-access-role OrgAdminRole [--exec] [-q] [-d|-dd]
    orgtoolconfigure distributed-config create --template-config ./spec_init_data.entity/config.yaml --child-config ~/.orgtool/dist1/config.yaml [--prefix dist1] --config ~/.orgtool/root/config.yaml  --ou-name dist1 --ou-path /root [--exec] [-q] [-d|-dd]
    orgtoolconfigure organization-unit create --config ~/.orgtool/root --ou-path /root/test [--exec] [-q] [-d|-dd]
    orgtoolconfigure validate --config <~/.orgtool/root [-q] [-d|-dd]

# IaC setup into an existing master account of an existing AWS Organization

The package provide the setup to initialize the deployment of an IaC pipeline into an existing AWS Organization. This use case helps customers started to use AWS Organization from the AW Console and wants to transition to an IaC pattern.

## Step1: Get information from your master account and how your AWS Organization is configured

You should get some information

1. you have to configure your local AWS CLI to access to the AWS Master Account of the AWS Organization you want to manage
   - To install the AWS CLI, https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html
   - Get programmatic access to the AWS Master Account of the AWS Organization, https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html

To test your configuration, you could run this command in your terminal:

    aws sts get-caller-identity

You should get a result like below where the "Account" and "Arn" value fit with your configuration:

    {
        "UserId": "AZERTYUIOPLKJHGFDSQWX",
        "Account": "123456789098",
        "Arn": "arn:aws:iam::123456789098:user/_username_"
    }

**2. You should get the name of the role you use to access to the organization member's AWS Account from the AWS Master Account.**

To test this role, you could run this command from your terminal:

    aws sts assume-role --role-arn arn:aws:iam::123456789098:role/OrgAdminRole --role-session-name AWSCLI-Session-OrgAdminRole

You should get this kind of result:

    {
        "Credentials": {
            "AccessKeyId": "********************",
            "SecretAccessKey": "******************************",
            "SessionToken": "*****************************************************",
            "Expiration": "*****************"
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "*************:AWSCLI-Session-OrgAdminRole",
            "Arn": "arn:aws:sts::123456789098:assumed-role/OrgAdminRole/AWSCLI-Session-OrgAdminRole"
        }
    }

## Step2: Run the setup:

To set the Infrastructure as code pipeline to manage your AWS Organization, you will run the script `init-deploy.sh` using your terminal (run `init-deploy.sh -h` to get help and details):

    bash init-deploy.sh -r OrgAdminRole

You should get a result like:

    Create S3 bucket and zip file for repo initialization
    make_bucket: tmp-c8130fc6739c9e85d55ab19faae7d5e5
    zip source.zip ./automation ./orgtool ./spec_init* *.py README.* LICENSE *.sh -r
    adding: automation/ (stored 0%)
    adding: automation/cc_git_lib.py (deflated 73%)
    adding: automation/cc_git_lib.readme.md (deflated 73%)
    adding: automation/orgformation.yaml (deflated 77%)
    adding: orgtool/ (stored 0%)
    adding: orgtool/validator.py (deflated 82%)
    ...
    ...
    ...
    upload: ./source.zip to s3://tmp-c8130fc6739c9e85d55ab19faae7d5e5/source.zip
    Deploy orgformation stack with OrgAccessRoleName=OrgAdminRole

    Waiting for changeset to be created..
    Waiting for stack create/update to complete
    Successfully created/updated stack - orgformation
    delete: s3://tmp-c8130fc6739c9e85d55ab19faae7d5e5/source.zip remove_bucket: tmp-c8130fc6739c9e85d55ab19faae7d5e5
    done

## Step3: You can look at your AWS Master account to look at the changes:

1. You have a stack deployed, orgformation.

2. This stack contains a CodeCommit repository, a CodePipeline and a CodeBuild.

3. The creation of the CodePipeline trigger its execution and the first run of the CodeBuild project.

4. the first run of the code build project will detect that the CodeCommit repository doesn't contain the AWS Organization description files, then the process will generate then by reverse engineering and will commit the files into the repository:

```
    organization/.orgtool/root/config.yaml
    organization/.orgtool/root/sepc.d/accounts.yaml
    organization/.orgtool/root/sepc.d/common.yaml
    organization/.orgtool/root/sepc.d/custom_policies.yaml
    organization/.orgtool/root/sepc.d/delegations.yaml
    organization/.orgtool/root/sepc.d/organizational_units.yaml
    organization/.orgtool/root/sepc.d/sc_policies.yaml
```

5. The commit of the description files will trigger a second execution of the AWS COdePipeline and the AWS CodeBuild project. This second execution will apply the AWS Organisation configuration to your organization. No worries, this will not generate changes because the configuration had just been generated by the previous build. This step validates that your Infrastructure as Code pipeline is working as expected.

6. You can check into the logs of the AWS CodeBuild project for the last execution. You should get at the end of the logs the content like below.

```
    [Container] 2021/09/27 14:07:45 Entering phase BUILD
    [Container] 2021/09/27 14:07:45 Running command echo "build ..."
    cd $CODEBUILD_SRC_DIR
    if [ -d "./organization/.orgtool/root" ]
    then
    echo "Organization found into the repo, then deploy the changes"
    echo "############ apply:"

    echo "##### run cmd: orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec"
    orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec

    echo "##### run cmd: orgtool organization --config ./organization/.orgtool/root/config.yaml --exec"
    orgtool organization --config ./organization/.orgtool/root/config.yaml --exec

    echo "##### run cmd: orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec"
    orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec

    echo "##### run cmd: orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec"
    orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec

    fi

    build ...
    Organization found into the repo, then deploy the changes
    ############ apply:
    ##### run cmd: orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec
    orgtool.utils: WARNING  Updated code from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    orgtool.utils: WARNING  New feature for recursive distributed configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    ##### run cmd: orgtool organization --config ./organization/.orgtool/root/config.yaml --exec
    orgtool.utils: WARNING  Updated code from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    orgtool.utils: WARNING  New feature for recursive distributed configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    ##### run cmd: orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec
    orgtool.utils: WARNING  Updated code from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    orgtool.utils: WARNING  New feature for recursive distributed configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    ##### run cmd: orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec
    orgtool.utils: WARNING  Updated code from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
    orgtool.utils: WARNING  New feature for recursive distributed configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020

    [Container] 2021/09/27 14:08:28 Phase complete: BUILD State: SUCCEEDED
    [Container] 2021/09/27 14:08:28 Phase context status code:  Message:
    [Container] 2021/09/27 14:08:28 Entering phase POST_BUILD
    [Container] 2021/09/27 14:08:28 Running command echo "post build ..."

    post build ...

    [Container] 2021/09/27 14:08:28 Phase complete: POST_BUILD State: SUCCEEDED
    [Container] 2021/09/27 14:08:28 Phase context status code:  Message:

```

## Step4: Make a change into your organization using Infrastructure as Code:

To do so, you will edit the AWS Organization configuration files stored into the AWS CodeCommit from the AWS Console.

1. Connect on the AWS Master Account using the AWS Console.

2. Open the CodeCommit Console, open the repository, navigate to /organization/.orgtool/root/spec.d

3. you can edit the configuration file appropriately following the change you want to perform. For example, we could add an Organization Unit above the root of the AWS Organization.

   1. Edit the file `organizational_units.yaml`

   2. Under `Child_OU` into `- Name: root`, you could add your Organization Unit. Below, we added an OU named `test`.

```
---
# Organizational Unit Specification.
#
# This specification maps the Organization's structure and assigns policies and
# accounts to organizational units.
#
# Each organizational_unit spec (OU) has the following attributes:
#   Name (str):     The name of the OU (required)
#   Ensure (str):   One of 'present' (default) or 'absent'.  Setting to
#                   'absent' will cause the OU to be deleted but
#                   only if no accounts are still assigned to the OU.
#   Accounts (list(str)):
#                   List of account names assigned to this OU.
#   SC_Policies (list(str)):
#                   List of Service Control Policies attached to this OU.
#   Child_OU (list(organizational_unit)):
#                   List of child Organizational Units (recursive structure).
#   IncludeConfigPath (string):
#                   Path to the config file of an orgtool configuration to include here for the tree and merge for the Accounts and SCPs
#                   The Name of OU is equal to the name of the upper OU in the included configuration
#   MountingOUPath (string):
#                   For an included configuration, this is the reference to the mounting point path into the OUs tree.
#                   This exist only if the upper name of the tree is not "root". if not, raise an exception
#                   The upper name of the tree is equal to the OU name of the mointing point
#   PrefixRequired:
#                   Only used with IncludeConfigPath.
#                   Prefix value to use to validate naming convention for included SCP name
#   Tags (dict):    Tags to apply to the AWS account. The tag value can have
#                   up to 256 characters.
#                   Valid characters: a-z, A-Z, 0-9, and . : + = @ _ / - (hyphen)


organizational_units:

- Name: root
  Accounts:
  - ...
  - ...

  Child_OU:

  # here the OU test added
  - Name: test
  # here the OU test added

  - Name: ...
    Accounts:
    - ....
```

4. Commit your change into the repository. The AWS CodePipeline will start and the AWS CodeBuild will deploy your change. Look at the AWS CodeBuild logs and/or AWS Organization console to control all want well.

## Step5: Perform AWS Organisation changes using the orgtool CLI.

**_WARNING: To stay resilient with the path, i recommend to use relative path into the repository where the Organization configuration is placed. By this way, you will have same resolution of the relative path when you manage the Organization configuration locally or in the CodeBuild project_**

You are ready now to go further: use a clone of the orgtool AWS Organization configuration, perform changes using the orgtool CLI and then commit the changes to make them deployed.

1. You will have to clone the AWS CodeCommit repository, https://docs.aws.amazon.com/codecommit/latest/userguide/getting-started.html

2. Use the orgtool cli (orgtoolconfigure) to perform Organization configuration changes. As an example, add an OU under `root` named `mytest`:

```
orgtoolconfigure organization-unit create --config organization/.orgtool/root/config.yaml --ou-path /root/mytest --exec
```

3. You should get the result like:

```
orgtool.utils: WARNING  New feature for IaC API to manipulate the configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
orgtool.utils: WARNING  New feature for recursive distributed configuration - fork from aws-orgs - Laurent Delhomme <delhom@amazon.com> AWS June 2020
orgtool.utils: INFO     organization-unit create done!
```

4. Commit your changes:

```
    git commit -a -m "Add mytest OU under root"
    git push origin main
```

5. Check the execution of the pipeline:

   The commit trigger the AWS CodePipeline, then the AWS CodeBuild project to run. The CodeBuild project will apply the changes, then add the Organization Unit `mytest` under `root`

## Step 6: Use advanced features to create a distributed configuration (Nested configuration embedded into the `root` configuration).

In large organization, you have some use-cases required to create isolated organization units (including its sub-resources, OUs, Accounts, SCP, Delegations, ...) into the same AWS Organization. Some use case delegate the management of these isolated `sub organizations`. Then `orgtool`provide an advanced feature to create an AWS Organization configuration composed by nested configuration into a `root`config.

The root configuration will have a pointer to the nested configuration, as below with the OU `dist1`:

```
---
# Organizational Unit Specification.
#
# This specification maps the Organization's structure and assigns policies and
# accounts to organizational units.
#
# Each organizational_unit spec (OU) has the following attributes:
#   Name (str):     The name of the OU (required)
#   Ensure (str):   One of 'present' (default) or 'absent'.  Setting to
#                   'absent' will cause the OU to be deleted but
#                   only if no accounts are still assigned to the OU.
#   Accounts (list(str)):
#                   List of account names assigned to this OU.
#   SC_Policies (list(str)):
#                   List of Service Control Policies attached to this OU.
#   Child_OU (list(organizational_unit)):
#                   List of child Organizational Units (recursive structure).
#   IncludeConfigPath (string):
#                   Path to the config file of an orgtool configuration to include here for the tree and merge for the Accounts and SCPs
#                   The Name of OU is equal to the name of the upper OU in the included configuration
#   MountingOUPath (string):
#                   For an included configuration, this is the reference to the mounting point path into the OUs tree.
#                   This exist only if the upper name of the tree is not "root". if not, raise an exception
#                   The upper name of the tree is equal to the OU name of the mointing point
#   PrefixRequired:
#                   Only used with IncludeConfigPath.
#                   Prefix value to use to validate naming convention for included SCP name
#   Tags (dict):    Tags to apply to the AWS account. The tag value can have
#                   up to 256 characters.
#                   Valid characters: a-z, A-Z, 0-9, and . : + = @ _ / - (hyphen)


organizational_units:

- Name: root
  Accounts:
  - 47b4a2fe8208409b9608b17b67939c3c
  - test
  Child_OU:
  - Name: test
    Accounts:
    - 6e34ded170f44f4b971e56d445ed771c
  - Name: dist1
    IncludeConfigPath: organization/.orgtool/dist1/config.yaml
    PrefixRequired: dist1

```

And the nested configuration `dist1`is set like:

```
# Organizational Unit Specification.
#
# This specification maps the Organization's structure and assigns policies and
# accounts to organizational units.
#
# Each organizational_unit spec (OU) has the following attributes:
#   Name (str):     The name of the OU (required)
#   Ensure (str):   One of 'present' (default) or 'absent'.  Setting to
#                   'absent' will cause the OU to be deleted but
#                   only if no accounts are still assigned to the OU.
#   Accounts (list(str)):
#                   List of account names assigned to this OU.
#   SC_Policies (list(str)):
#                   List of Service Control Policies attached to this OU.
#   Child_OU (list(organizational_unit)):
#                   List of child Organizational Units (recursive structure).
#   IncludeConfigPath (string):
#                   Path to the config file of an orgtool configuration to include here for the tree and merge for the Accounts and SCPs
#                   The Name of OU is equal to the name of the upper OU in the included configuration
#   MountingOUPath (string):
#                   For an included configuration, this is the reference to the mounting point path into the OUs tree.
#                   This exist only if the upper name of the tree is not "root". if not, raise an exception
#                   The upper name of the tree is equal to the OU name of the mointing point
#   PrefixRequired:
#                   Only used with IncludeConfigPath.
#                   Prefix value to use to validate naming convention for included SCP name


organizational_units:
- Name: dist1
  MountingOUPath: /root
```

To create a distributed configuration, you can use the orgtool CLI command, `orgtoolconfigure distributed-config create`

```
orgtoolconfigure distributed-config create --template-config spec_init_data.blank/config.yaml --child-config organization/.orgtool/dist1/config.yaml --prefix dist1 --config organization/.orgtool/root/config.yaml  --ou-name dist1 --ou-path /root --exec [-q] [-d|-dd]
```

Like for any changes, you will commit the changes to trigger the AWS CodePipeline, then the AWS CodeBuild to make this changes applied to your organization.

Using distributed configuration, you can create templated nested configuration as it is shared into `spec_init_data.entity` where you will find a configuration containing a list of OUs.

```
---
# Organizational Unit Specification.
#
# This specification maps the Organization's structure and assigns policies and
# accounts to organizational units.
#
# Each organizational_unit spec (OU) has the following attributes:
#   Name (str):     The name of the OU (required)
#   Ensure (str):   One of 'present' (default) or 'absent'.  Setting to
#                   'absent' will cause the OU to be deleted but
#                   only if no accounts are still assigned to the OU.
#   Accounts (list(str)):
#                   List of account names assigned to this OU.
#   SC_Policies (list(str)):
#                   List of Service Control Policies attached to this OU.
#   Child_OU (list(organizational_unit)):
#                   List of child Organizational Units (recursive structure).
#   IncludeConfigPath (string):
#                   Path to the config file of an orgtool configuration to include here for the tree and merge for the Accounts and SCPs
#                   The Name of OU is equal to the name of the upper OU in the included configuration
#   MountingOUPath (string):
#                   For an included configuration, this is the reference to the mounting point path into the OUs tree.
#                   This exist only if the upper name of the tree is not "root". if not, raise an exception
#                   The upper name of the tree is equal to the OU name of the mointing point
#   PrefixRequired:
#                   Only used with IncludeConfigPath.
#                   Prefix value to use to validate naming convention for included SCP name


organizational_units:
- Name: Name
  MountingOUPath: MountingOUPath
  Child_OU:
  - Name: admin       # admin OU where tool and audit account are located
  - Name: managed     # managed OU where accounts strictly compliant are located
  - Name: unmanaged   # unmanaged OU for account not able to sustain strict compliance
  - Name: trash       # trash OU for account to be decommissioned definitally
  - Name: recycled    # recycled OU for account to be reused
```

You can use this template by running the command below to create `dist2` nested configuration under `root`:

```
orgtoolconfigure distributed-config create --template-config ./spec_init_data.entity/config.yaml --child-config organization/.orgtool/dist2/config.yaml --prefix dist2 --config organization/.orgtool/root/config.yaml  --ou-name dist2 --ou-path /root --exec [-q] [-d|-dd]
```

## Conclusion:

`orgtool` is a powerful tool to help customers to manage their AWS Organization with code. In collaboration with CodeCommit, CodePipeline and CodeBuild, customer build powerful landing zone including the manage of large AWS Organization where many team share the same top level configuration and run independently into their dedicated space.

This tool was originally based upon a fork of https://github.com/ucopacme/aws-orgs by Ashley Gould agould@ucop.edu

Author: Laurent Delhomme (delhom@amazon.com), David Hessler (dhhessl@amazon.com)

Version: 0.9.1

## License Summary

The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
