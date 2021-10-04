

set -o pipefail
shopt -s expand_aliases
declare -ig __oo__insideTryCatch=0

# if try-catch is nested, then set +e before so the parent handler doesn't catch us
alias try="[[ \$__oo__insideTryCatch -gt 0 ]] && set +e;
           __oo__insideTryCatch+=1; ( set -e;
           trap \"Exception.Capture \${LINENO}; \" ERR;"
alias catch=" ); Exception.Extract \$? || "

Exception.Capture() {
    local script="${BASH_SOURCE[1]#./}"

    if [[ ! -f /tmp/stored_exception_source ]]; then
        echo "$script" > /tmp/stored_exception_source
    fi
    if [[ ! -f /tmp/stored_exception_line ]]; then
        echo "$1" > /tmp/stored_exception_line
    fi
    return 0
}

Exception.Extract() {
    if [[ $__oo__insideTryCatch -gt 1 ]]
    then
        set -e
    fi

    __oo__insideTryCatch+=-1

    __EXCEPTION_CATCH__=( $(Exception.GetLastException) )

    local retVal=$1
    if [[ $retVal -gt 0 ]]
    then
        # BACKWARDS COMPATIBILE WAY:
        # export __EXCEPTION_SOURCE__="${__EXCEPTION_CATCH__[(${#__EXCEPTION_CATCH__[@]}-1)]}"
        # export __EXCEPTION_LINE__="${__EXCEPTION_CATCH__[(${#__EXCEPTION_CATCH__[@]}-2)]}"
        export __EXCEPTION_SOURCE__="${__EXCEPTION_CATCH__[-1]}"
        export __EXCEPTION_LINE__="${__EXCEPTION_CATCH__[-2]}"
        export __EXCEPTION__="${__EXCEPTION_CATCH__[@]:0:(${#__EXCEPTION_CATCH__[@]} - 2)}"
        return 1 # so that we may continue with a "catch"
    fi
}

Exception.GetLastException() {
    if [[ -f /tmp/stored_exception ]] && [[ -f /tmp/stored_exception_line ]] && [[ -f /tmp/stored_exception_source ]]
    then
        cat /tmp/stored_exception
        cat /tmp/stored_exception_line
        cat /tmp/stored_exception_source
    else
        echo -e " \n${BASH_LINENO[1]}\n${BASH_SOURCE[2]#./}"
    fi

    rm -f /tmp/stored_exception /tmp/stored_exception_line /tmp/stored_exception_source
    return 0
}

try {
    
    echo "check if ./organization/.orgtool is into the source / if not, git clone, reverse setup, git commit, then exit."
    echo "Next build will deploy for configuration just saved into the repo."

    if [ ! -d "./organization/.orgtool/root" ] 
    then
        echo "orgtool configuration is not yet setup into the ${OrganisationConfigurationCodeCommitName} repository." 

        git config --global credential.helper '!aws codecommit credential-helper $@'
        git config --global credential.UseHttpPath true
        git config --global user.email "orgtoolconfigure@${ACCOUNT_ID}.aws"
        git config --global user.name "orgtoolconfigure"

        echo 'Install git-remote-codecommit'
        pip install git-remote-codecommit
        git clone codecommit::${AWS_REGION}://${OrganisationConfigurationCodeCommitName} --branch ${BranchName}
        # ls -R -lsa

        cd ${OrganisationConfigurationCodeCommitName}
        echo "current directory is $(pwd)"

        HEAD_COMMIT_ID=$(git show -s HEAD --pretty=format:%H)
        echo "HEAD_COMMIT_ID is $HEAD_COMMIT_ID"

        orgtoolconfigure reverse-setup --template-dir "./spec_init_data.blank" --output-dir "./organization/.orgtool/root"  --master-account-id "${ACCOUNT_ID}" --org-access-role "${OrgAccessRole}" --exec        

        git add -A
        git commit -a -m "Organization configuration initialized"
        git push origin ${BranchName}

    fi

    cd $CODEBUILD_SRC_DIR

    if [ -d "./organization/.orgtool/root" ] 
    then
        echo "Organization found into the repo, then deploy the changes"

        echo "##### run cmd: orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec"
        orgtoolaccounts create --config ./organization/.orgtool/root/config.yaml --exec

        echo "##### run cmd: orgtool organization --config ./organization/.orgtool/root/config.yaml --exec"
        orgtool organization --config ./organization/.orgtool/root/config.yaml --exec

        echo "##### run cmd: orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec"
        orgtoolaccounts update --config ./organization/.orgtool/root/config.yaml --exec

        echo "##### run cmd: orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec"
        orgtoolauth delegations --config ./organization/.orgtool/root/config.yaml --exec

    fi


} catch {
    echo "Error in $__EXCEPTION_SOURCE__ at line: $__EXCEPTION_LINE__!"    
    exit 1
}
