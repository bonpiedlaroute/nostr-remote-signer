# Shared by the scripts of enclave/aws: the region, the names, the AWS CLI bound to that region.
#
# AWS_REGION: eu-west-3 by default. BUNKER_AWS_NAME: the role, its instance profile, the key's
# alias, the instance, its security group and key pair; bunker-vault-dev by default.

REGION=${AWS_REGION:-eu-west-3}
NAME=${BUNKER_AWS_NAME:-bunker-vault-dev}

aws() { command aws --region "$REGION" "$@"; }
die() { echo "$*" >&2; exit 1; }
