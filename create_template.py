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

from docopt import docopt
import json
from troposphere import Template, GetAtt, StackName, Ref, Join, Region, AccountId, Sub, Parameter
from troposphere_dns_certificate.certificatemanager import Certificate
import troposphere.iam as iam
import troposphere.awslambda as awslambda
import troposphere.apigateway as apigateway
import troposphere.route53 as route53
import troposphere.cloudfront as cloudfront
import troposphere.dynamodb as dynamodb
import troposphere.s3 as s3

from awacs.aws import PolicyDocument, Statement, Allow, Action, Principal

LAMBDA_PACKAGE_BUCKET = 'terraform-registry-build'

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

        self.domain = Ref(self.add_parameter(Parameter(
            'DomainName',
            Type='String',
            Description='The domain name to deploy to'
        )))

        self.hosted_zone = Ref(self.add_parameter(Parameter(
            'HostedZone',
            Type='AWS::Route53::HostedZone::Id',
            Description='The hosted zone'
        )))

        self.add_module_bucket()
        self.add_api_token_table()
        self.add_lambda_function()
        self.add_api()

    def add_module_bucket(self: Template):
        self._bucket = self.add_resource(s3.Bucket(
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
                                Resource=[GetAtt(self._bucket, 'Arn'), Join('', [GetAtt(self._bucket, 'Arn'), '/*'])]
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

        self._lambda_function = self.add_resource(awslambda.Function(
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
                    'TerraformModules': Ref(self._bucket),
                    'ApiTokens': Ref(self._api_token_table)
                }
            )
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

    def add_service_discovery_api(self, rest_api: apigateway.RestApi):
        well_known = self.add_resource(apigateway.Resource(
            'Apiwellknown',
            RestApiId=Ref(rest_api),
            PathPart='.well-known',
            ParentId=GetAtt(rest_api, 'RootResourceId'),
        ))

        terraform_json = self.add_resource(apigateway.Resource(
            'Apiwellknownterraformjson',
            RestApiId=Ref(rest_api),
            PathPart='terraform.json',
            ParentId=Ref(well_known)
        ))

        service_discovery = self.add_resource(apigateway.Method(
            'GETwellknownterraformjson',
            RestApiId=Ref(rest_api),
            ResourceId=Ref(terraform_json),
            AuthorizationType='NONE',
            HttpMethod='GET',
            Integration=apigateway.Integration(
                'GETwellknownterraformjsonIntegration',
                Type='MOCK',
                IntegrationResponses=[apigateway.IntegrationResponse(
                    StatusCode='200',

                    ResponseTemplates={
                        'application/json':  json.dumps({'modules.v1': '/v1/'})
                    }
                )],
                RequestTemplates={
                    'application/json': json.dumps({'statusCode': 200})
                },
            ),
            MethodResponses=[apigateway.MethodResponse(
                StatusCode='200',
                ResponseModels={
                    'application/json': 'Empty'
                }
            )]
        ))

        return service_discovery

    def add_registry_api(self, rest_api: apigateway.RestApi):
        v1 = self.add_resource(apigateway.Resource(
            'Apiv1',
            RestApiId=Ref(rest_api),
            PathPart='v1',
            ParentId=GetAtt(rest_api, 'RootResourceId'),
        ))

        download_redirect = self.add_resource(apigateway.Resource(
            'DownloadRedirect',
            RestApiId=Ref(rest_api),
            PathPart='download.tar.gz',
            ParentId=GetAtt(rest_api, 'RootResourceId'),
        ))

        namespace = self.add_resource(apigateway.Resource(
            'ApiNamespace',
            RestApiId=Ref(rest_api),
            PathPart='{namespace}',
            ParentId=Ref(v1),
        ))

        name = self.add_resource(apigateway.Resource(
            'ApiName',
            RestApiId=Ref(rest_api),
            PathPart='{name}',
            ParentId=Ref(namespace),
        ))

        provider = self.add_resource(apigateway.Resource(
            'ApiProvider',
            RestApiId=Ref(rest_api),
            PathPart='{provider}',
            ParentId=Ref(name),
        ))

        version = self.add_resource(apigateway.Resource(
            'ApiVersion',
            RestApiId=Ref(rest_api),
            PathPart='{version}',
            ParentId=Ref(provider),
        ))

        download = self.add_resource(apigateway.Resource(
            'ApiDownload',
            RestApiId=Ref(rest_api),
            PathPart='download',
            ParentId=Ref(version),
        ))

        def add_method(resource):
            return self.add_resource(apigateway.Method(
                f'GET{resource.title}',
                RestApiId=Ref(rest_api),
                ResourceId=Ref(resource),
                AuthorizationType='NONE',
                HttpMethod='GET',
                Integration=apigateway.Integration(
                    f'GET{resource.title}Integration',
                    Type='AWS_PROXY',
                    Uri=Join('', ['arn:aws:apigateway:', Region, ':lambda:path/2015-03-31/functions/',
                                  GetAtt(self._lambda_function, 'Arn'), '/invocations']),
                    IntegrationHttpMethod='POST'
                )
            ))

        return [add_method(x) for x in [version, download, download_redirect]]

    def add_api(self):
        rest_api = self.add_resource(apigateway.RestApi(
            'Api',
            Description=Sub('${AWS::StackName} Terraform Registry'),
            Name=StackName
        ))

        methods = self.add_registry_api(rest_api)

        self.add_resource(awslambda.Permission(
            f'ApigatewayPermission',
            Principal='apigateway.amazonaws.com',
            Action='lambda:InvokeFunction',
            FunctionName=GetAtt(self._lambda_function, 'Arn'),
            SourceArn=Join('', ['arn:aws:execute-api:', Region, ':', AccountId, ':', Ref(rest_api), '/*'])
        ))

        methods += [self.add_service_discovery_api(rest_api)]

        deployment = self.add_resource(apigateway.Deployment(
            'ApiDeployment',
            Description=Sub('${AWS::StackName} Terraform Registry'),
            RestApiId=Ref(rest_api),
            DependsOn=methods
        ))

        stage = self.add_resource(apigateway.Stage(
            'ApiStage',
            MethodSettings=[apigateway.MethodSetting(
                HttpMethod='*',
                LoggingLevel='INFO',
                MetricsEnabled=True,
                ResourcePath='/*',
                DataTraceEnabled=True,
            )],
            TracingEnabled=True,
            StageName='prd',
            RestApiId=Ref(rest_api),
            DeploymentId=Ref(deployment)
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
