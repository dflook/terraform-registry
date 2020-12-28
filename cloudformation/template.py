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
from typing import Tuple

import troposphere.apigatewayv2 as apigatewayv2
import troposphere.awslambda as awslambda
import troposphere.dynamodb as dynamodb
import troposphere.iam as iam
import troposphere.route53 as route53
from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal
from docopt import docopt
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Parameter, Retain
from troposphere_dns_certificate.certificatemanager import Certificate

from provider_registry import add_provider_registry
from login import add_login
from module_registry import add_module_registry
from provider_mirror import add_provider_mirror
from service_discovery import add_service_discovery

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
        self.add_parameter_to_group(self.domain, 'Deployment Domain')

        self.github_client_id = self.add_parameter(Parameter(
            'GitHubClientId',
            Type='String',
            Description='The GitHub App OAuth Client Id'
        ))
        self.set_parameter_label(self.github_client_id, 'GitHub Client ID')
        self.add_parameter_to_group(self.domain, 'GitHub OAuth')

        self.github_client_secret = self.add_parameter(Parameter(
            'GitHubClientSecret',
            Type='String',
            Description='The GitHub App OAuth Client Secret'
        ))
        self.set_parameter_label(self.github_client_secret, 'GitHub Client Secret')
        self.add_parameter_to_group(self.domain, 'GitHub OAuth')

        self.admin_email = self.add_parameter(Parameter(
            'AdminEmail',
            Type='String',
            Description='The email address of the master admin user'
        ))
        self.set_parameter_label(self.github_client_secret, 'Admin user email address')
        self.add_parameter_to_group(self.domain, 'GitHub OAuth')

        certificate = self.add_certificate()

        api_tokens_table = self.add_api_token_table()

        ui_api = self.add_ui(certificate)

        module_api_url = add_module_registry(self, api_tokens_table)
        provider_api_url = add_provider_registry(self, api_tokens_table)
        login_api_url = add_login(self, api_tokens_table)

        add_service_discovery(self,
                              ui_api,
                              module_api_url=module_api_url,
                              login_api_url=login_api_url,
                              provider_api_url=provider_api_url)
        add_provider_mirror(self, ui_api)

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

    def add_ui(self, certificate):
        role = self.add_resource(iam.Role(
            'UiLambdaRole',
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
        version_name = 'Ui' + hex_sha256

        lambda_function = self.add_resource(awslambda.Function(
            'UiLambda',
            Runtime='python3.8',
            Code=awslambda.Code(
                S3Bucket=LAMBDA_PACKAGE_BUCKET,
                S3Key=f'lambda/{hex_sha256}.zip'
            ),
            Handler='ui.handler',
            Timeout=25,
            Role=GetAtt(role, 'Arn'),
            Description=Sub('${AWS::StackName} UI'),
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
