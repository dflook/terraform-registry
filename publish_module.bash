#!/usr/bin/env bash

set -e

readonly BUCKET=$1
readonly MODULE_NAME=$2
readonly VERSION=$3
readonly MODULE_PATH=$4

DIR=$(pwd)

function finish {
  cd $DIR
  rm -f $DIR/$VERSION.tar.gz
}

trap finish EXIT

cd $MODULE_PATH
tar -czvf $DIR/$VERSION.tar.gz *

aws s3 cp $DIR/$VERSION.tar.gz s3://$BUCKET/$MODULE_NAME/$VERSION.tar.gz
