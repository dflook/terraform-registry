#!/usr/bin/env bash

set -e

readonly REGISTRY_URL=$1
readonly MODULE_NAME=$2
readonly VERSION=$3
readonly MODULE_PATH=$4

readonly API_TOKEN="Thisismytoken"

if [ "$MODULE_PATH" = "" ]; then
    echo "Usage: ./publish_modules.bash <registry_url> <namespace>/<name>/<provider> <version> <path>"
    exit 2
fi

DIR=$(pwd)

function finish {
  cd $DIR
  rm -f $DIR/$VERSION.tar.gz
}

trap finish EXIT

cd $MODULE_PATH
tar -czvf $DIR/$VERSION.tar.gz *

MODULE_REGISTRY_PATH=$(curl --fail --silent --location https://$REGISTRY_URL/.well-known/terraform.json | jq -r '."modules.v1"')
curl --location --fail -X PUT https://$REGISTRY_URL$MODULE_REGISTRY_PATH$MODULE_NAME/$VERSION/upload --data-binary "@$DIR/$VERSION.tar.gz" -H "Content-Type: application/x-tar" -H "Authorization: Bearer $API_TOKEN"
