#!/bin/bash

set -e

if [ -z $DYNAMODB_HOME ]; then
  DYNAMODB_HOME=`pwd`/dynamodb;
fi

echo "Dynamodb home: ${DYNAMODB_HOME}"
trap "kill 0" EXIT
java -Djava.library.path=${DYNAMODB_HOME}/DynamoDBLocal_lib -jar ${DYNAMODB_HOME}/DynamoDBLocal.jar -sharedDb $@
