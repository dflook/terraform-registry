#!/usr/bin/env python3

import base64
import hashlib
from typing import Tuple

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.iam as iam
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere import Template, GetAtt, Ref, Sub, Retain, Join
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal, Condition, Bool, Deny

import troposphere.awslambda as awslambda
import troposphere.iam as iam
import troposphere.s3 as s3

LAMBDA_PACKAGE_BUCKET = 'dflook-terraform-registry'


def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


def add_provider_mirror(template: Template, api):

    bucket = template.add_resource(s3.Bucket(
        'TerraformMirror',
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
        'TerraformMirrorBucketPolicy',
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

    role = template.add_resource(iam.Role(
        'ProviderMirrorLambdaRole',
        AssumeRolePolicyDocument=PolicyDocument(
            Version='2012-10-17',
            Statement=[Statement(
                Effect=Allow,
                Action=[Action('sts', 'AssumeRole')],
                Principal=Principal('Service', 'lambda.amazonaws.com')
            )]
        ),
        ManagedPolicyArns=['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
    ))

    aws_sha256, hex_sha256 = sha256('build/lambda.zip')
    version_name = 'ProviderMirror' + hex_sha256

    lambda_function = template.add_resource(awslambda.Function(
        'ProviderMirrorLambda',
        Runtime='python3.8',
        Code=awslambda.Code(
            S3Bucket=LAMBDA_PACKAGE_BUCKET,
            S3Key=f'lambda/{hex_sha256}.zip'
        ),
        Handler='provider_mirror.handler',
        Timeout=300,
        Role=GetAtt(role, 'Arn'),
        Description=Sub('${AWS::StackName} Terraform Provider Mirror'),
        Environment=awslambda.Environment(
            Variables={
                'MirrorBucket': Ref(bucket)
            }
        )
    ))

    lambda_version = template.add_resource(awslambda.Version(
        version_name,
        CodeSha256=aws_sha256,
        Description=hex_sha256,
        FunctionName=Ref(lambda_function),
        DeletionPolicy=Retain
    ))

    integration = template.add_resource(apigatewayv2.Integration(
        'ProviderMirrorIntegration',
        ApiId=Ref(api),
        Description='Service Discovery API',
        IntegrationType='AWS_PROXY',
        IntegrationUri=Ref(lambda_version),
        PayloadFormatVersion='2.0'
    ))

    template.add_resource(apigatewayv2.Route(
        'ProviderMirrorIndexRoute',
        ApiId=Ref(api),
        RouteKey='GET /{hostname}/{namespace}/{type}/{version}',
        Target=Join('/', ['integrations', Ref(integration)])
    ))
