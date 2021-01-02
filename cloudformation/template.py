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
from typing import Tuple, Dict

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.dynamodb as dynamodb
import troposphere.iam as iam
import troposphere.route53 as route53
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from docopt import docopt
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Parameter, Retain, s3
from troposphere_dns_certificate.certificatemanager import Certificate
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal, Condition, Bool, Deny

LAMBDA_PACKAGE_BUCKET = 'terraform-registry-build'


def sha256(path) -> Tuple[str, str]:
    with open(path, 'rb') as f:
        h = hashlib.sha256(f.read())

    aws_sha256 = base64.b64encode(h.digest()).decode()
    hex_sha256 = h.hexdigest()
    return aws_sha256, hex_sha256


class TerraformRegistryTemplate(Template):

    def __init__(self, build_version='0.0.1', *args, **kwargs):
        super().__init__(
            Description='Terraform Registry',
            Metadata={
                'Comment': 'This template has been generated.',
                'Version': build_version
            }
        )

        self.set_version()

        self.domain = self.add_parameter(Parameter(
            'DomainName',
            Type='String',
            Description='The domain name to deploy to'
        ))
        self.set_parameter_label(self.domain, 'Domain Name')
        self.add_parameter_to_group(self.domain, 'Deployment Domain')

        self.hosted_zone = self.add_parameter(Parameter(
            'HostedZone',
            Type='AWS::Route53::HostedZone::Id',
            Description='The hosted zone'
        ))
        self.set_parameter_label(self.hosted_zone, 'Hosted Zone')
        self.add_parameter_to_group(self.hosted_zone, 'Deployment Domain')

        self.github_client_id = self.add_parameter(Parameter(
            'GitHubClientId',
            Type='String',
            Description='The GitHub App OAuth Client Id'
        ))
        self.set_parameter_label(self.github_client_id, 'GitHub Client ID')
        self.add_parameter_to_group(self.github_client_id, 'GitHub OAuth')

        self.github_client_secret = self.add_parameter(Parameter(
            'GitHubClientSecret',
            Type='String',
            Description='The GitHub App OAuth Client Secret'
        ))
        self.set_parameter_label(self.github_client_secret, 'GitHub Client Secret')
        self.add_parameter_to_group(self.github_client_secret, 'GitHub OAuth')

        self.admin_email = self.add_parameter(Parameter(
            'AdminEmail',
            Type='String',
            Description='The email address of the master admin user'
        ))
        self.set_parameter_label(self.admin_email, 'Admin user email address')
        self.add_parameter_to_group(self.admin_email, 'GitHub OAuth')

        certificate = self.add_certificate()

        #api_tokens_table = self.add_api_token_table()

        s3_buckets = { bucket_name: self.add_bucket(bucket_name) for bucket_name in ['TerraformModules']}

        dynamodb_tables = {
            'Sessions': self.add_session_table()
        }

        self.add_apigateway(certificate, dynamodb_tables, s3_buckets)

    def add_bucket(self, bucket_name):
        bucket = self.add_resource(s3.Bucket(
            bucket_name,
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
            f'{bucket_name}BucketPolicy',
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

    def add_certificate(self):
        return self.add_resource(Certificate(
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

    def add_api_token_table(self):
        return self.add_resource(dynamodb.Table(
            'ApiTokens',
            TableName=Sub('${AWS::StackName}ApiTokens'),
            AttributeDefinitions=[
                dynamodb.AttributeDefinition(AttributeName='token', AttributeType='S')
            ],
            BillingMode='PAY_PER_REQUEST',
            KeySchema=[
                dynamodb.KeySchema(AttributeName='token', KeyType='HASH')
            ],
            SSESpecification=dynamodb.SSESpecification(SSEEnabled=True),
            TimeToLiveSpecification=dynamodb.TimeToLiveSpecification(
                AttributeName='exp',
                Enabled=True
            )
        ))

    def add_session_table(self):
        return self.add_resource(dynamodb.Table(
            'Sessions',
            TableName=Sub('${AWS::StackName}Sessions'),
            AttributeDefinitions=[
                dynamodb.AttributeDefinition(AttributeName='session_id', AttributeType='S')
            ],
            BillingMode='PAY_PER_REQUEST',
            KeySchema=[
                dynamodb.KeySchema(AttributeName='session_id', KeyType='HASH')
            ],
            SSESpecification=dynamodb.SSESpecification(SSEEnabled=True),
            TimeToLiveSpecification=dynamodb.TimeToLiveSpecification(
                AttributeName='exp',
                Enabled=True
            )
        ))

    def add_apigateway(self, certificate, dynamodb_tables: Dict, s3_buckets: Dict):
        role = self.add_resource(iam.Role(
            'UiLambdaRole',
            AssumeRolePolicyDocument=PolicyDocument(
                Version='2012-10-17',
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[Action('sts', 'AssumeRole')],
                        Principal=Principal('Service', 'lambda.amazonaws.com')
                    )
                ]
            ),
            ManagedPolicyArns=['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
            Policies=[
                iam.Policy(
                    PolicyName='Sessions',
                    PolicyDocument=PolicyDocument(
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[Action('dynamodb', '*')],
                                Resource=[GetAtt(table, 'Arn') for table in dynamodb_tables.values()]
                            ),
                            Statement(
                                Effect=Allow,
                                Action=[Action('s3', '*')],
                                Resource=[
                                    GetAtt(bucket, 'Arn') for bucket in s3_buckets.values()
                                ] + [
                                    Join('', [GetAtt(bucket, 'Arn'), '/*']) for bucket in s3_buckets.values()
                                ]
                            ),
                        ]
                    )
                )
            ]
        ))

        aws_sha256, hex_sha256 = sha256('build/lambda.zip')
        version_name = 'Ui' + hex_sha256

        lambda_function = self.add_resource(awslambda.Function(
            'UiLambda',
            Runtime='python3.8',
            Code=awslambda.Code(
                S3Bucket=LAMBDA_PACKAGE_BUCKET,
                S3Key=f'lambda/{hex_sha256}.zip'
            ),
            Handler='apigateway_entrypoint.handler',
            Timeout=25,
            Role=GetAtt(role, 'Arn'),
            Description=Sub('${AWS::StackName} UI'),
            Environment=awslambda.Environment(
                Variables={
                    'GITHUB_CLIENT_ID': Ref(self.github_client_id),
                    'GITHUB_CLIENT_SECRET': Ref(self.github_client_secret),
                    **{f'{k}Table': Ref(v) for k, v in dynamodb_tables.items()},
                    **{f'{k}Bucket': Ref(v) for k, v in s3_buckets.items()}
                }
            )
        ))

        lambda_version = self.add_resource(awslambda.Version(
            version_name,
            CodeSha256=aws_sha256,
            Description=hex_sha256,
            FunctionName=Ref(lambda_function),
            DeletionPolicy=Retain
        ))

        api = self.add_resource(apigatewayv2.Api(
            'UiHttpApi',
            Name=StackName,
            Description=Join(' ', [Ref(self.domain), 'Terraform Services']),
            ProtocolType='HTTP',
            Target=Ref(lambda_version),
        ))

        self.add_resource(awslambda.Permission(
            'UiHttpApiGatewayPermission',
            Principal='apigateway.amazonaws.com',
            Action='lambda:InvokeFunction',
            FunctionName=Ref(lambda_version),
            SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(api), '/*'])
        ))

        domain = self.add_resource(apigatewayv2.DomainName(
            'UiDomain',
            DomainName=Ref(self.domain),
            DomainNameConfigurations=[
                apigatewayv2.DomainNameConfiguration(
                    CertificateArn=Ref(certificate),
                )
            ]
        ))

        self.add_resource(apigatewayv2.ApiMapping(
            'UiMapping',
            DomainName=Ref(domain),
            ApiId=Ref(api),
            Stage='$default'
        ))

        self.add_resource(route53.RecordSetGroup(
            'UiDnsRecord',
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

        return api


def main(arguments):
    version = arguments['<VERSION>']

    template = TerraformRegistryTemplate(version)

    if arguments['--output']:
        with open(arguments['--output'], 'w') as f:
            f.write(template.to_yaml())
    else:
        print(template.to_yaml())


if __name__ == '__main__':
    arguments = docopt(__doc__, version='0.0.1')
    main(arguments)
