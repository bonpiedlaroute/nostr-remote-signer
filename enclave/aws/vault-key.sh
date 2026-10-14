#!/usr/bin/env bash
# The vault's KMS key and the parent instance's role, with the AWS CLI (v2).
#
#   enclave/aws/vault-key.sh create          the role, with no permission of its own, and the
#                                            key: nobody may decrypt yet
#   enclave/aws/vault-key.sh pin <pcr0>      the role may decrypt, from an enclave running that
#                                            image only
#   enclave/aws/vault-key.sh policy [pcr0]   print the key policy, change nothing
#   enclave/aws/vault-key.sh destroy         the key goes after 7 days, the role at once
#
# Region and names: see common.sh.
set -euo pipefail

# shellcheck source=enclave/aws/common.sh
. "$(dirname "$0")/common.sh"
ALIAS=alias/$NAME

key_arn() { aws kms describe-key --key-id "$ALIAS" --query KeyMetadata.Arn --output text; }

# The account administers the key and seals with it, but never decrypts: the default policy
# would let IAM grant Decrypt to anyone, the parent's role included. No grants either.
policy() {
    local pcr0=${1:-} account
    if [ -n "$pcr0" ]; then
        [[ $pcr0 =~ ^[0-9a-f]{96}$ ]] || die "pcr0: 96 lowercase hex digits expected"
        # A debug enclave reports zeros: pinning them would admit any image.
        [[ ! $pcr0 =~ ^0+$ ]] || die "pcr0: all zeros is what a debug enclave reports"
    fi
    account=$(aws sts get-caller-identity --query Account --output text)
    jq -n --arg account "$account" --arg role "$NAME" --arg pcr0 "$pcr0" '{
        Version: "2012-10-17",
        Statement: ([
            {
                Sid: "Administer, never decrypt",
                Effect: "Allow",
                Principal: { AWS: "arn:aws:iam::\($account):root" },
                Action: [
                    "kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*",
                    "kms:Put*", "kms:Update*", "kms:Disable*", "kms:Get*", "kms:Delete*",
                    "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand"
                ],
                Resource: "*"
            },
            {
                Sid: "Seal",
                Effect: "Allow",
                Principal: { AWS: "arn:aws:iam::\($account):root" },
                Action: "kms:Encrypt",
                Resource: "*"
            }
        ] + if $pcr0 == "" then [] else [{
                Sid: "Open in the attested enclave only",
                Effect: "Allow",
                Principal: { AWS: "arn:aws:iam::\($account):role/\($role)" },
                Action: "kms:Decrypt",
                Resource: "*",
                Condition: {
                    StringEqualsIgnoreCase: { "kms:RecipientAttestation:ImageSha384": $pcr0 }
                }
            }] end)
    }'
}

create() {
    if aws iam get-role --role-name "$NAME" >/dev/null 2>&1 || key_arn >/dev/null 2>&1; then
        die "$NAME already exists: run destroy first"
    fi
    local doc arn
    doc=$(policy)
    # The parent's role has no permission policy: it gets only what the key policy grants.
    aws iam create-role --role-name "$NAME" --description "The vault's parent instance" \
        --assume-role-policy-document '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}' >/dev/null
    aws iam create-instance-profile --instance-profile-name "$NAME" >/dev/null
    aws iam add-role-to-instance-profile --instance-profile-name "$NAME" --role-name "$NAME"
    arn=$(aws kms create-key --description "The vault's data keys ($NAME)" --policy "$doc" \
        --query KeyMetadata.Arn --output text)
    aws kms create-alias --alias-name "$ALIAS" --target-key-id "$arn"
    echo "role: $NAME (instance profile $NAME)"
    echo "key:  $arn ($ALIAS)"
}

pin() {
    local doc
    doc=$(policy "$1")
    aws kms put-key-policy --key-id "$(key_arn)" --policy-name default --policy "$doc"
    echo "$ALIAS: Decrypt for role $NAME, from an enclave with PCR0 $1 only"
}

destroy() {
    local arn
    if arn=$(key_arn 2>/dev/null); then
        aws kms delete-alias --alias-name "$ALIAS"
        aws kms schedule-key-deletion --key-id "$arn" --pending-window-in-days 7 >/dev/null
        echo "key $arn: deleted in 7 days, unless aws kms cancel-key-deletion"
    fi
    if aws iam get-instance-profile --instance-profile-name "$NAME" >/dev/null 2>&1; then
        aws iam remove-role-from-instance-profile --instance-profile-name "$NAME" \
            --role-name "$NAME" 2>/dev/null || true
        aws iam delete-instance-profile --instance-profile-name "$NAME"
    fi
    if aws iam get-role --role-name "$NAME" >/dev/null 2>&1; then
        aws iam delete-role --role-name "$NAME"
    fi
    echo "role and instance profile $NAME: gone"
}

case ${1:-} in
    create) create ;;
    pin) pin "${2:?usage: $0 pin <pcr0>}" ;;
    policy) policy "${2:-}" ;;
    destroy) destroy ;;
    *) die "usage: $0 create | pin <pcr0> | policy [pcr0] | destroy" ;;
esac
