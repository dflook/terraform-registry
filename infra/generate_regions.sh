#!/usr/bin/env bash

set -e

REGIONS=$(aws ec2 describe-regions | jq '.Regions[].RegionName' -r)

rm -f regions.tf

for REGION in $REGIONS; do
  REGION=$REGION envsubst <regions.tf.template >> regions.tf
done
