#!/usr/bin/env python
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


class MergeConflict(Exception):
    pass


def commit(client, repositoryName, input_folder, authorName, email, commitMessage, subdirectories=[""], branchName="master", expectedHead=""):
    '''
    client: boto3.get_client("codecommit")
    repositoryName: Repository Name in the code commit of the account to which client connects
    input_folder: Folder which contains the files to commit. The whole content of input_folder will be commited
    authorName: author of the commit
    email: Email of the author
    commitMessage: Commit message
    subdirectories: subdirectories which should be considered for this commit. This must be a list of substrings of the relative path with the input_folder as root. See README.md for example.
    branchName: Name of the branch to which it should be commited
    expectedHead:
        expected commitId of the HEAD of the repository.
        If the expectedHead does not match the actual HEAD of the repository, then another commit was performed in the meantime.
        This means there is a risk of a potential merge conflict => cancelt the commit
    '''
    print("Commit", input_folder, "to repository", repositoryName)
    try:
        response_branch = client.get_branch(repositoryName=repositoryName, branchName=branchName)
        parentCommitId = response_branch["branch"]["commitId"]
        # Create Commit
        put_files, delete_files = _create_commit(client, input_folder, repositoryName, subdirectories)

        if expectedHead != "":
            # Compare extectedHead with actual Head
            if parentCommitId != expectedHead:
                logger.info("Expected HEAD does not match actual HEAD of repository. Potential merge conflict. Cancel the commit.")
                raise MergeConflict("Expected HEAD does not match actual HEAD of repository.")
        logger.info("Put following files: " + str([f["filePath"] for f in put_files]))
        logger.info("Delete following files: " + str(delete_files))
        try:
            response = client.create_commit(
                repositoryName=repositoryName,
                branchName=branchName,
                parentCommitId=parentCommitId,
                authorName=authorName,
                email=email,
                commitMessage=commitMessage,
                putFiles=put_files,
                deleteFiles=delete_files
            )
            logger.info("create_commit response is %s" % response)
        except client.exceptions.NoChangeException as e:
            print("No changes discovered. No commit performed.")
            raise e
    except client.exceptions.BranchDoesNotExistException as e:
        # Create initial commit
        logger.info("BranchDoesNotExistException is %s" % e)
        client.put_file(repositoryName=repositoryName, branchName=branchName, fileContent="", filePath="README.md", commitMessage="init", name=authorName, email=email)
        commit(client, repositoryName, input_folder, authorName, email, commitMessage, branchName=branchName)


def clone(client, repositoryName, output_folder, branchName="master"):
    '''
    client: boto3.get_client("codecommit")
    repositoryName: Repository Name in the code commit of the account to which client connects
    output_folder: Folder to which the repository will be cloned
    branchName: Name of the branch
    '''
    print("clone repository", repositoryName, "and write to", output_folder)
    response = client.get_branch(repositoryName=repositoryName, branchName=branchName)
    commitId = response["branch"]["commitId"]
    checkout(client, repositoryName, commitId, output_folder)
    return response


def checkout(client, repositoryName, commitId, output_folder):
    '''
    client: boto3.get_client("codecommit")
    repositoryName: Repository Name in the code commit of the account to which client connects
    commitId: Commit ID which shall be checked out
    output_folder: Folder to which the repository will be cloned
    '''
    print("Checkout commit", commitId, "from repository", repositoryName, "and write to", output_folder)

    files_in_repo = _traverse_tree_list_files_in_repo([], client, repositoryName, commitId)
    logger.info("Checkout following files: " + str(files_in_repo))
    try:
        os.makedirs(output_folder)
    except FileExistsError:
        pass
    for f in files_in_repo:
        logger.info("file: {}".format(f))
        try:
            os.makedirs(os.path.join(output_folder, os.path.split(f)[0]))
        except FileExistsError:
            pass
        output_path = os.path.join(output_folder, f)
        logger.debug(output_path)
        response = client.get_file(repositoryName=repositoryName, commitSpecifier=commitId, filePath=f)
        with open(output_path, "wb") as out_file:
            out_file.write(response["fileContent"])


def _create_commit(client, input_folder, repositoryName, subdirectories, branchName="master"):
    put_files = _list_local_files(input_folder, subdirectories)
    response = client.get_branch(repositoryName=repositoryName, branchName=branchName)
    commitId = response["branch"]["commitId"]
    files_in_repo = _traverse_tree_list_files_in_repo([], client, repositoryName, commitId)
    delete_files = []
    for r in files_in_repo:
        R_IN_LOCAL_FILES = False
        for put_file in put_files:
            if put_file["filePath"] == r:
                R_IN_LOCAL_FILES = True
        if not R_IN_LOCAL_FILES and any([s in r for s in subdirectories]):
            delete_files.append({"filePath": r})
    return put_files, delete_files


def _traverse_tree_list_files_in_repo(files_in_repo, client, repositoryName, commitId, folderPath="/"):
    response = client.get_folder(repositoryName=repositoryName, commitSpecifier=commitId, folderPath=folderPath)
    # Traverse through repository
    for folder in response["subFolders"]:
        files_in_repo = _traverse_tree_list_files_in_repo(files_in_repo, client, repositoryName, commitId, folderPath=folder["absolutePath"])

    # Add files to files_in_repo
    for file in response["files"]:
        files_in_repo.append(file["absolutePath"])
    return files_in_repo


def _list_local_files(folder, subdirectories):
    # List local files
    put_files = []
    ls = os.walk(folder)
    for item in ls:
        if not any([s in item[0] for s in subdirectories]):
            continue
        for file_name in item[-1]:
            abs_item = os.path.join(item[0], file_name)
            with open(abs_item, "rb") as f:
                put_files.append({"filePath": abs_item[len(folder) + 1::], "fileContent": f.read()})
    return put_files
