#!/bin/sh
java -Djava.library.path=${HOME}/Programms/dynamodb_local/DynamoDBLocal_lib -jar ${HOME}/Programms/dynamodb_local/DynamoDBLocal.jar -sharedDb
