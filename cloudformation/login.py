#!/usr/bin/env python3

import base64
import hashlib
from typing import Tuple

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.dynamodb as dynamodb
import troposphere.iam as iam
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Retain

LAMBDA_PACKAGE_BUCKET = 'dflook-terraform-registry'


def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


def add_login(template: Template, api_token_table):
    def add_users_table():
        return template.add_resource(dynamodb.Table(
            'Users',
            TableName=Sub('${AWS::StackName}Users'),
            AttributeDefinitions=[
                dynamodb.AttributeDefinition(AttributeName='email', AttributeType='S')
            ],
            BillingMode='PAY_PER_REQUEST',
            KeySchema=[
                dynamodb.KeySchema(AttributeName='email', KeyType='HASH')
            ],
            SSESpecification=dynamodb.SSESpecification(SSEEnabled=True)
        ))

    def add_auth_code_table():
        return template.add_resource(dynamodb.Table(
            'AuthCodes',
            TableName=Sub('${AWS::StackName}AuthCodes'),
            AttributeDefinitions=[
                dynamodb.AttributeDefinition(AttributeName='code', AttributeType='S')
            ],
            BillingMode='PAY_PER_REQUEST',
            KeySchema=[
                dynamodb.KeySchema(AttributeName='code', KeyType='HASH')
            ],
            SSESpecification=dynamodb.SSESpecification(SSEEnabled=True),
            TimeToLiveSpecification=dynamodb.TimeToLiveSpecification(
                AttributeName='exp',
                Enabled=True
            )
        ))

    def add_lambda(users_table, auth_code_table):
        role = template.add_resource(iam.Role(
            'LoginLambdaRole',
            AssumeRolePolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[Statement(
                    Effect=Allow,
                    Action=[Action('sts', 'AssumeRole')],
                    Principal=Principal('Service', 'lambda.amazonaws.com')
                )]
            ),
            ManagedPolicyArns=['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
            Policies=[
                iam.Policy(
                    PolicyName='Registry',
                    PolicyDocument=PolicyDocument(
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(api_token_table, 'Arn')]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(users_table, 'Arn')]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(auth_code_table, 'Arn')]
                            )
                        ]
                    )
                )
            ]
        ))

        aws_sha256, hex_sha256 = sha256('build/lambda.zip')
        version_name = 'Login' + hex_sha256

        lambda_function = template.add_resource(awslambda.Function(
            'LoginLambda',
            Runtime='python3.8',
            Code=awslambda.Code(
                S3Bucket=LAMBDA_PACKAGE_BUCKET,
                S3Key=f'lambda/{hex_sha256}.zip'
            ),
            Handler='login_v1.handler',
            Timeout=300,
            Role=GetAtt(role, 'Arn'),
            Description=Sub('${AWS::StackName} Terraform Login API'),
            Environment=awslambda.Environment(
                Variables={
                    'ApiTokens': Ref(api_token_table),
                    'Users': Ref(users_table),
                    'AuthCodes': Ref(auth_code_table)
                }
            )
        ))

        return template.add_resource(awslambda.Version(
            version_name,
            CodeSha256=aws_sha256,
            Description=hex_sha256,
            FunctionName=Ref(lambda_function),
            DeletionPolicy=Retain
        ))

    def add_api(func):
        api = template.add_resource(apigatewayv2.Api(
            'LoginHttpApi',
            Name=StackName,
            Description='Terraform Cli Login',
            ProtocolType='HTTP',
            Target=Ref(func),
        ))

        template.add_resource(awslambda.Permission(
            'LoginHttpApiGatewayPermission',
            Principal='apigateway.amazonaws.com',
            Action='lambda:InvokeFunction',
            FunctionName=Ref(func),
            SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(api), '/*'])
        ))

        return api

    auth_code_table = add_auth_code_table()
    users_table = add_users_table()
    func = add_lambda(users_table, auth_code_table)
    api = add_api(func)
    return GetAtt(api, 'ApiEndpoint')
