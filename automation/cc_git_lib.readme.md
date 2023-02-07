# cc_git_lib

## Introduction

A boto3 implementation of rudimentary git functionalities (commit, clone, checkout) for AWS CodeCommit repositories

### git commit

`cc_git_lib.commit(BOTO3_CODECOMMIT_CLIENT, REPOSITORY_NAME, INPUT_FOLDER, AUTHOR_NAME, EMAIL, COMMIT-MESSAGE)`
This pushes the content of the INPUT_FOLDER to the REPOSITORY_NAME repository. It overwrites all the files in the repository with the same name and deletes all files in the repo which are not present in the INPUT_FOLDER.
If the content of INPUT_FOLDER and the REPOSITORY_NAME repository is the same, nothing happens.

### git clone

`cc_git_lib.clone(BOTO3_CODECOMMIT_CLIENT, REPOSITORY_NAME, OUTPUT_FOLDER, BRANCHNAME="master")`
This creates an `output` folder containing the content of the repository of the head of the branch BRANCHNAME. By default, the BRANCHNAME is "master".

### git checkout

`cc_git_lib.checkout(BOTO3_CODECOMMIT_CLIENT, REPOSITORY_NAME, COMMIT_ID, OUTPUT_FOLDER)`
This creates an OUTPUT folder containing the content of the repository REPOSITORY_NAME at the commit COMMIT_ID.

#### Examples

##### cc_git_lig.commit()

```
#!/usr/bin/env python
import boto3
import cc_git_lib

session = boto3.Session()
cc = session.client("codecommit")

cc_git_lib.commit(cc, "testrepo", "input", "author-name", "email@example.com", "commitmessage-example")
```

```
INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Commit output to repository aws-orgs-on-lambda
INFO:root:Put following files: ['aws-orgs.yml', 'README.md', 'awsconfigure/app.py', 'artefact.yml', 'asawfa', 'deploy.sh', 'deploy_artefact.sh', 'test.sh']
INFO:root:Delete following files: []
```

This pushes the content of the "input" folder to the "testrepo" repository. It overwrites all the files in the repository with the same name and deletes all files in the repo which are not present in the "input" folder.
If the content of the "input" folder and the "testrepo" repository is the same, nothing happens.

##### Commit subdirectories

Let's assume following structure of the repository. The local copy of this repository is saved in a folder called "input".

```
.
├── README.md
├── artefact.yml
├── asawfa
├── aws-orgs.yml
├── awsconfigure
│   └── app.py
├── deploy.sh
├── deploy_artefact.sh
├── sub_test
│   └── sub_sub_test
│       └── new_file.txt
├── new_file
└── test.sh
```

With the following command you can update (put and delete changes) for the subdirectory `sub_test/sub_sub_test` only:

```
cc_git_lib.commit(cc, "testrepo", "input", "author-name", "email@example.com", "commitmessage-example", subdirectories=["sub_test/sub_sub_test"])
```

```
INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Commit output to repository testrepo
INFO:root:Put following files: ['sub_test/sub_sub_test/new_file.txt']
INFO:root:Delete following files: []
```

As a comparison, the same change without specifying the subdirectory:

```
cc_git_lib.commit(cc, "testrepo", "input", "author-name", "email@example.com", "commitmessage-example")
```

```
INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Commit output to repository testrepo
INFO:root:Put following files: ['aws-orgs.yml', 'README.md', 'artefact.yml', 'asawfa', 'deploy.sh', 'new_file', 'deploy_artefact.sh', 'test.sh', 'awsconfigure/app.py', 'sub_test/sub_sub_test/new_file.txt']
INFO:root:Delete following files: []
```

You can add multiple subdirectories into the `subdirectories` list if you want to commit the content of multiple subdirectories.

##### Compare expectedHead with actual HEAD of repository

To avoid a potential merge conflict, you can pass the `expectedHead` to the `cc_git_lib.commit()` function and ensure, that a commit only is performed, if no other commit has been done in the meanwhile.

```
#!/usr/bin/env python
import boto3
import cc_git_lib

session = boto3.Session()
cc = session.client("codecommit")

response = cc_git_lib.clone(cc, "aws-orgs-on-lambda", "output")
expectedHead = response["branch"]["commitId"]

# perform changes ...

try:
  cc_git_lib.commit(cc, "testrepo", "input", "author-name", "email@example.com", "commitmessage-example", expectedHead = expectedHead)
except cc_git_lib.MergeConflict:
  print("Another commit has been performed after pulling the repository. No commit has been performed. Retry!")
```

If the `expectedHead` does not match the actual head of the repository, a `cc_git_lib.MergeConflict` exception is raised.

##### cc_git_lig.clone()

```
#!/usr/bin/env python
import boto3
import cc_git_lib

session = boto3.Session()
cc = session.client("codecommit")

cc_git_lib.clone(cc, "aws-orgs-on-lambda", "output")
```

```
INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Checkout commit 065d44f0c0272e1725a6a3443bbf3189103e82b9 from repository aws-orgs-on-lambda and write to output :
INFO:root:Checkout following files: ['awsconfigure/app.py', 'README.md', 'artefact.yml', 'aws-orgs.yml', 'deploy.sh', 'deploy_artefact.sh', 'test.sh']
```

This created an `output` folder containing the content of the repository of the head of the master branch.

##### cc_git_lig.checkout()

```
#!/usr/bin/env python
import boto3
import cc_git_lib

session = boto3.Session()
cc = session.client("codecommit")

cc_git_lib.checkout(cc, "aws-orgs-on-lambda", "90ff0697bf351a09ee200ed46deccff2294491d7", "output") # pragma: allowlist secret
```

```
INFO:botocore.credentials:Found credentials in shared credentials file: ~/.aws/credentials
Checkout commit 90ff0697bf351a09ee200ed46deccff2294491d7 from repository aws-orgs-on-lambda and write to output :
INFO:root:Checkout following files: ['awsconfigure/app.py', 'README.md', 'artefact.yml', 'aws-orgs.yml', 'deploy.sh', 'deploy_artefact.sh', 'test.sh']
```

This created an `output` folder containing the content of the repository at given commit
