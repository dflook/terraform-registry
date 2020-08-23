#!/usr/bin/env bash

set -e

readonly REGISTRY_HOST=$1
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

curl -L https://
curl -L -X PUT https://$REGISTRY_HOST/v1/$MODULE_NAME/$VERSION/upload --data-binary "@$DIR/$VERSION.tar.gz" -H "Content-Type: application/x-tar" -H "Authorization: Bearer $API_TOKEN"
