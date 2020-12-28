#!/usr/bin/env python3

import base64
import hashlib
from typing import Tuple

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.iam as iam
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from troposphere import Template, GetAtt, Ref, Join, Region, AccountId, Sub, Retain

LAMBDA_PACKAGE_BUCKET = 'terraform-registry-build'


def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


def add_service_discovery(template: Template, api, *, module_api_url: str = None, login_api_url: str = None,
                          provider_api_url: str = None):
    """
    Add the terraform service discovery protocol to an API Gateway
    """

    role = template.add_resource(iam.Role(
        'ServiceDiscoveryLambdaRole',
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
    version_name = 'ServiceDiscovery' + hex_sha256

    lambda_function = template.add_resource(awslambda.Function(
        'ServiceDiscoveryLambda',
        Runtime='python3.8',
        Code=awslambda.Code(
            S3Bucket=LAMBDA_PACKAGE_BUCKET,
            S3Key=f'lambda/{hex_sha256}.zip'
        ),
        Handler='service_discovery.handler',
        Timeout=300,
        Role=GetAtt(role, 'Arn'),
        Description=Sub('${AWS::StackName} Terraform Service Discovery'),
        Environment=awslambda.Environment(
            Variables={
                'modules_v1': module_api_url,
                'login_v1': login_api_url,
                'providers_v1': provider_api_url
            }
        )
    ))

    template.add_resource(awslambda.Permission(
        f'ServiceDiscoveryApigatewayPermission',
        Principal='apigateway.amazonaws.com',
        Action='lambda:InvokeFunction',
        FunctionName=Ref(lambda_function),
        SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(api), '/*'])
    ))

    lambda_version = template.add_resource(awslambda.Version(
        version_name,
        CodeSha256=aws_sha256,
        Description=hex_sha256,
        FunctionName=Ref(lambda_function),
        DeletionPolicy=Retain
    ))

    integration = template.add_resource(apigatewayv2.Integration(
        'ServiceDiscoveryIntegration',
        ApiId=Ref(api),
        Description='Service Discovery API',
        IntegrationType='AWS_PROXY',
        IntegrationUri=Ref(lambda_version),
        PayloadFormatVersion='2.0'
    ))

    template.add_resource(apigatewayv2.Route(
        'ServiceDiscoveryRoute',
        ApiId=Ref(api),
        RouteKey='GET /.well-known/terraform.json',
        Target=Join('/', ['integrations', Ref(integration)])
    ))
