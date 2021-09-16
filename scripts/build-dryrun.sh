
echo "############ dryrun:"
set -e

echo "##### run cmd: orgtool organization --config ./organization/.orgtool/config.yaml"
orgtool organization --config ./organization/.orgtool/config.yaml

echo "##### run cmd: awsaccounts create --config ./organization/.orgtool/config.yaml"
awsaccounts create --config ./organization/.orgtool/config.yaml

echo "##### run cmd: awsaccounts update --config ./organization/.orgtool/config.yaml"
awsaccounts update --config ./organization/.orgtool/config.yaml
