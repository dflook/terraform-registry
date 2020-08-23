#!/usr/bin/env python3
"""
Create the terraform registry cloudformation template

Usage:
    create_template.py [<VERSION>] [--output <PATH>]
    create_template.py (-h | --help)
    create_template.py (-v | --version)

Options:
    <VERSION>          The version of this template
    --output <PATH>    The file to write the template to
    --help      Show this screen
    --version   Print the version of this tool

"""
import base64
import hashlib
import random
import string
from typing import Tuple

from docopt import docopt
import json
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Parameter, Retain
from troposphere_dns_certificate.certificatemanager import Certificate
import troposphere.iam as iam
import troposphere.awslambda as awslambda
import troposphere.apigatewayv2 as apigatewayv2
import troposphere.route53 as route53
import troposphere.cloudfront as cloudfront
import troposphere.dynamodb as dynamodb
import troposphere.s3 as s3

from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal, Condition, Bool, Deny

LAMBDA_PACKAGE_BUCKET = 'terraform-registry-build'

def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


class TerraformRegistryTemplate(Template):

    def __init__(self, build_version, *args, **kwargs):
        super().__init__(
            Description='Terraform Registry',
            Metadata={
                'Comment': 'This template has been generated.',
                'Version': build_version
            }
        )

        self._build_version = build_version

        self.set_version()

        self.domain = self.add_parameter(Parameter(
            'DomainName',
            Type='String',
            Description='The domain name to deploy to'
        ))

        self.hosted_zone = self.add_parameter(Parameter(
            'HostedZone',
            Type='AWS::Route53::HostedZone::Id',
            Description='The hosted zone'
        ))

        self.add_module_bucket()
        self.add_provider_bucket()
        self.add_api_token_table()
        self.add_lambda_function()
        self.add_certificate()
        self.add_api()

    def add_module_bucket(self: Template):
        self._module_bucket = self.add_resource(s3.Bucket(
            'TerraformModules',
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

        self.add_resource(s3.BucketPolicy(
            'TerraformModulesBucketPolicy',
            Bucket=Ref(self._module_bucket),
            PolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Deny,
                        Action=[Action('s3', 'GetObject')],
                        Principal=Principal('*'),
                        Resource=[Join('', ['arn:aws:s3:::', Ref(self._module_bucket), '/*'])],
                        Condition=Condition(
                            Bool({
                                'aws:SecureTransport': False
                            })
                        )
                    ),
                    Statement(
                        Effect=Deny,
                        Action=[Action('s3', 'GetObject')],
                        Principal=Principal('*'),
                        Resource=[Join('', ['arn:aws:s3:::', Ref(self._module_bucket), '/*'])],
                        Condition=Condition(
                            Bool({
                                'aws:SecureTransport': False
                            })
                        )
                    )
                ]
            ),
        ))

    def add_provider_bucket(self: Template):
        self._provider_bucket = self.add_resource(s3.Bucket(
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

        self.add_resource(s3.BucketPolicy(
            'TerraformProvidersBucketPolicy',
            Bucket=Ref(self._provider_bucket),
            PolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Deny,
                        Action=[Action('s3', 'GetObject')],
                        Principal=Principal('*'),
                        Resource=[Join('', ['arn:aws:s3:::', Ref(self._provider_bucket), '/*'])],
                        Condition=Condition(
                            Bool({
                                'aws:SecureTransport': False
                            })
                        )
                    ),
                    Statement(
                        Effect=Deny,
                        Action=[Action('s3', 'GetObject')],
                        Principal=Principal('*'),
                        Resource=[Join('', ['arn:aws:s3:::', Ref(self._provider_bucket), '/*'])],
                        Condition=Condition(
                            Bool({
                                'aws:SecureTransport': False
                            })
                        )
                    )
                ]
            ),
        ))


    def add_lambda_function(self):
        role = self.add_resource(iam.Role(
            'TerraformRegistryLambdaRole',
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
                                    GetAtt(self._module_bucket, 'Arn'),
                                    Join('', [GetAtt(self._module_bucket, 'Arn'), '/*']),
                                    GetAtt(self._provider_bucket, 'Arn'),
                                    Join('', [GetAtt(self._provider_bucket, 'Arn'), '/*'])
                                ]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(self._api_token_table, 'Arn')]
                            )
                        ]
                    )
                )
            ]
        ))

        lambda_function = self.add_resource(awslambda.Function(
            'TerraformRegistry',
            Runtime='python3.7',
            Code=awslambda.Code(
                S3Bucket=LAMBDA_PACKAGE_BUCKET,
                S3Key=f'{self._build_version}/lambda.zip'
            ),
            Handler='registry.handler',
            Timeout=300,
            Role=GetAtt(role, 'Arn'),
            Description=Sub('${AWS::StackName} Terraform Registry'),
            Environment=awslambda.Environment(
                Variables={
                    'TerraformModules': Ref(self._module_bucket),
                    'ProviderBucket': Ref(self._provider_bucket),
                    'ApiTokens': Ref(self._api_token_table)
                }
            )
        ))

        aws_sha256, hex_sha256 = sha256('build/lambda.zip')
        version_name = 'TerraformRegistryVersion' + hex_sha256

        self._lambda_function = self.add_resource(awslambda.Version(
            version_name,
            CodeSha256=aws_sha256,
            Description=hex_sha256,
            FunctionName=Ref(lambda_function),
            DependsOn=[lambda_function],
            DeletionPolicy=Retain
        ))

    def add_api_token_table(self):

        self._api_token_table = self.add_resource(dynamodb.Table(
            'ApiTokens',
            TableName=Sub('${AWS::StackName}ApiTokens'),
            AttributeDefinitions=[
                dynamodb.AttributeDefinition(AttributeName='token', AttributeType='S')
            ],
            BillingMode='PAY_PER_REQUEST',
            KeySchema=[
                dynamodb.KeySchema(AttributeName='token', KeyType='HASH')
            ],
            SSESpecification=dynamodb.SSESpecification(SSEEnabled=True)
        ))

    def add_certificate(self):
        self.certificate = self.add_resource(Certificate(
            'GlobalCertificate',
            ValidationMethod='DNS',
            DomainName=Ref(self.domain),
            DomainValidationOptions=[
                {
                    'DomainName': Ref(self.domain),
                    'HostedZoneId': Ref(self.hosted_zone)
                }
            ],
            Tags=[{
                'Key': 'Name',
                'Value': Ref(self.domain)
            }]
        ))

    def add_api(self):
        api = self.add_resource(apigatewayv2.Api(
            'HttpApi',
            Name=StackName,
            Description=Join(' ', [Ref(self.domain), 'Terraform Registry']),
            ProtocolType='HTTP',
            Target=Ref(self._lambda_function),
        ))

        self.add_resource(awslambda.Permission(
            f'ApigatewayPermission',
            Principal='apigateway.amazonaws.com',
            Action='lambda:InvokeFunction',
            FunctionName=Ref(self._lambda_function),
            SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(api), '/*'])
        ))

        domain = self.add_resource(apigatewayv2.DomainName(
            'HttpApiDomain',
            DomainName=Ref(self.domain),
            DomainNameConfigurations=[
                apigatewayv2.DomainNameConfiguration(
                    CertificateArn=Ref(self.certificate),
                )
            ]
        ))

        mapping = self.add_resource(apigatewayv2.ApiMapping(
            'Mapping',
            DomainName=Ref(domain),
            ApiId=Ref(api),
            Stage='$default'
        ))

        dns_record = self.add_resource(route53.RecordSetGroup(
            'ApiDnsRecord',
            HostedZoneId=Ref(self.hosted_zone),
            RecordSets=[route53.RecordSet(
                Name=Ref(self.domain),
                AliasTarget=route53.AliasTarget(
                    DNSName=GetAtt(domain, 'RegionalDomainName'),
                    HostedZoneId=GetAtt(domain, 'RegionalHostedZoneId')
                ),
                Type='A'
            )]
        ))

def main(arguments):
    version = arguments['<VERSION>']

    template = TerraformRegistryTemplate(version)

    if arguments['--output']:
        with open(arguments['--output'], 'w') as f:
            f.write(template.to_yaml())
    else:
        print(template.to_yaml())

if __name__ == '__main__':
    arguments = docopt(__doc__, version='create_template.py')
    main(arguments)
