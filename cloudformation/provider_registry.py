#!/usr/bin/env python3

import base64
import hashlib
from typing import Tuple

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.iam as iam
import troposphere.s3 as s3
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal, Condition, Bool, Deny
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Retain

LAMBDA_PACKAGE_BUCKET = 'dflook-terraform-registry'


def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


def add_provider_registry(template: Template, api_token_table):
    def add_bucket():
        bucket = template.add_resource(s3.Bucket(
            'TerraformProviders',
            AccessControl='Private',
            BucketEncryption=s3.BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    s3.ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(SSEAlgorithm='AES256')
                    )
                ]
            ),
            PublicAccessBlockConfiguration=s3.PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True
            )
        ))

        template.add_resource(s3.BucketPolicy(
            'TerraformProvidersBucketPolicy',
            Bucket=Ref(bucket),
            PolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Deny,
                        Action=[Action('s3', '*')],
                        Principal=Principal('*'),
                        Resource=[Join('', ['arn:aws:s3:::', Ref(bucket), '/*'])],
                        Condition=Condition(
                            Bool({
                                'aws:SecureTransport': False
                            })
                        )
                    )
                ]
            ),
        ))

        return bucket

    def add_lambda(bucket):
        role = template.add_resource(iam.Role(
            'ProviderRegistryLambdaRole',
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
                                Action=[Action('s3', '*')],
                                Resource=[
                                    GetAtt(bucket, 'Arn'),
                                    Join('', [GetAtt(bucket, 'Arn'), '/*']),
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(api_token_table, 'Arn')]
                            )
                        ]
                    )
                )
            ]
        ))

        aws_sha256, hex_sha256 = sha256('build/lambda.zip')
        version_name = 'Provider' + hex_sha256

        lambda_function = template.add_resource(awslambda.Function(
            'ProviderRegistry',
            Runtime='python3.8',
            Code=awslambda.Code(
                S3Bucket=LAMBDA_PACKAGE_BUCKET,
                S3Key=f'lambda/{hex_sha256}.zip'
            ),
            Handler='modules_v1.handler',
            Timeout=300,
            Role=GetAtt(role, 'Arn'),
            Description=Sub('${AWS::StackName} Terraform Registry'),
            Environment=awslambda.Environment(
                Variables={
                    'ModuleBucket': Ref(bucket),
                    'ApiTokens': Ref(api_token_table)
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
            'ProviderRegistryHttpApi',
            Name=StackName,
            Description='Terraform Provider Registry',
            ProtocolType='HTTP',
            Target=Ref(func),
        ))

        template.add_resource(awslambda.Permission(
            'ProviderRegistryHttpApiGatewayPermission',
            Principal='apigateway.amazonaws.com',
            Action='lambda:InvokeFunction',
            FunctionName=Ref(func),
            SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(api), '/*'])
        ))

        return api

    bucket = add_bucket()
    func = add_lambda(bucket)
    api = add_api(func)
    return GetAtt(api, 'ApiEndpoint')
