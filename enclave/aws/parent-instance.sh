#!/usr/bin/env bash
# The vault's parent instance on EC2, with the AWS CLI (v2): enclaves enabled, in the default
# VPC, SSH open to this machine's public address only, the role of vault-key.sh as profile.
#
#   enclave/aws/parent-instance.sh launch      the key pair, the security group, the instance
#   enclave/aws/parent-instance.sh terminate   the instance, its security group and key pair
#
# Region and names: see common.sh. BUNKER_EC2_TYPE: m5.xlarge by default, 4 vCPUs of which
# the enclave takes 2.
set -euo pipefail

# shellcheck source=enclave/aws/common.sh
. "$(dirname "$0")/common.sh"
TYPE=${BUNKER_EC2_TYPE:-m5.xlarge}
KEY_FILE=$(cd "$(dirname "$0")/.." && pwd)/out/$NAME.pem
AMI=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64

# Run once by cloud-init, as root: nitro-cli, and 2 vCPUs and 2 GiB set aside for the enclave.
SETUP='#!/bin/bash
set -euxo pipefail
dnf install -y aws-nitro-enclaves-cli socat jq
sed -i "s/^memory_mib:.*/memory_mib: 2048/; s/^cpu_count:.*/cpu_count: 2/" \
    /etc/nitro_enclaves/allocator.yaml
systemctl enable --now nitro-enclaves-allocator.service
usermod -aG ne ec2-user'

instances() {
    aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text \
        --filters "Name=tag:Name,Values=$NAME" \
        "Name=instance-state-name,Values=pending,running,stopping,stopped"
}

launch() {
    [ -z "$(instances)" ] || die "$NAME is already running: terminate it first"
    local ip ami sg id
    ip=$(curl -fsS https://checkip.amazonaws.com)
    ami=$(aws ssm get-parameter --name "$AMI" --query Parameter.Value --output text)
    mkdir -p "$(dirname "$KEY_FILE")"
    # The private key exists on this machine only.
    (umask 077 && aws ec2 create-key-pair --key-name "$NAME" --key-type ed25519 \
        --query KeyMaterial --output text > "$KEY_FILE")
    sg=$(aws ec2 create-security-group --group-name "$NAME" \
        --description "SSH to the vault parent instance, from one address" \
        --query GroupId --output text)
    aws ec2 authorize-security-group-ingress --group-id "$sg" \
        --protocol tcp --port 22 --cidr "$ip/32" >/dev/null
    id=$(aws ec2 run-instances --image-id "$ami" --instance-type "$TYPE" \
        --key-name "$NAME" --security-group-ids "$sg" --iam-instance-profile "Name=$NAME" \
        --enclave-options Enabled=true --metadata-options HttpTokens=required \
        --user-data "$SETUP" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
        --query 'Instances[0].InstanceId' --output text)
    aws ec2 wait instance-running --instance-ids "$id"
    ip=$(aws ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    echo "instance $id ($TYPE), billed until terminate"
    echo "ssh -i $KEY_FILE ec2-user@$ip"
}

terminate() {
    local ids sg
    read -ra ids <<< "$(instances)"
    if [ ${#ids[@]} -gt 0 ]; then
        aws ec2 terminate-instances --instance-ids "${ids[@]}" >/dev/null
        aws ec2 wait instance-terminated --instance-ids "${ids[@]}"
        echo "instance ${ids[*]}: terminated"
    fi
    sg=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$NAME" \
        --query 'SecurityGroups[].GroupId' --output text)
    [ -z "$sg" ] || aws ec2 delete-security-group --group-id "$sg"
    aws ec2 delete-key-pair --key-name "$NAME" >/dev/null
    rm -f "$KEY_FILE"
    echo "security group and key pair $NAME: gone"
}

case ${1:-} in
    launch) launch ;;
    terminate) terminate ;;
    *) die "usage: $0 launch | terminate" ;;
esac
