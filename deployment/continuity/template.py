"""Generate an isolated pilot revocation stack; no existing ID is migrated."""
import json
from pathlib import Path


def template():
    code = Path(__file__).with_name('authority.py').read_text()
    resources = {
        'Ledger': {'Type': 'AWS::DynamoDB::Table', 'DeletionPolicy': 'Retain',
            'UpdateReplacePolicy': 'Retain', 'Properties': {
                'BillingMode': 'PAY_PER_REQUEST', 'DeletionProtectionEnabled': True,
                'AttributeDefinitions': [{'AttributeName': 'credential', 'AttributeType': 'S'}],
                'KeySchema': [{'AttributeName': 'credential', 'KeyType': 'HASH'}],
                'SSESpecification': {'SSEEnabled': True},
                'PointInTimeRecoverySpecification': {'PointInTimeRecoveryEnabled': True},
                'OnDemandThroughput': {'MaxReadRequestUnits': 5, 'MaxWriteRequestUnits': 5}}},
        'Api': {'Type': 'AWS::ApiGatewayV2::Api', 'Properties': {
            'Name': 'openid-pilot-revocation', 'ProtocolType': 'HTTP'}},
        'Stage': {'Type': 'AWS::ApiGatewayV2::Stage', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'StageName': '$default', 'AutoDeploy': True,
            'DefaultRouteSettings': {'ThrottlingBurstLimit': 5, 'ThrottlingRateLimit': 0.1}}},
    }
    for name, handler, actions in [
        ('Backend', 'backend_handler', ['dynamodb:GetItem', 'dynamodb:UpdateItem']),
        ('Public', 'public_handler', ['dynamodb:UpdateItem'])
    ]:
        resources[name+'Role'] = {'Type': 'AWS::IAM::Role', 'Properties': {
            'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]},
            'Policies': [{'PolicyName': 'ledger-only', 'PolicyDocument': {
                'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': actions,
                    'Resource': {'Fn::GetAtt': ['Ledger', 'Arn']}}]}}]}}
        resources[name] = {'Type': 'AWS::Lambda::Function', 'Properties': {
            'Runtime': 'python3.12', 'Handler': 'index.'+handler, 'MemorySize': 512,
            'Timeout': 8, 'ReservedConcurrentExecutions': 2,
            'Role': {'Fn::GetAtt': [name+'Role', 'Arn']},
            'Environment': {'Variables': {'REVOCATION_TABLE': {'Ref': 'Ledger'},
                'TEST_BETA_MODE': {'Ref': 'TestBetaMode'}}},
            'Code': {'ZipFile': code}}}
    resources.update({
        'Integration': {'Type': 'AWS::ApiGatewayV2::Integration', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'IntegrationType': 'AWS_PROXY',
            'IntegrationUri': {'Fn::GetAtt': ['Public', 'Arn']}, 'PayloadFormatVersion': '2.0',
            'TimeoutInMillis': 10000}},
        'Route': {'Type': 'AWS::ApiGatewayV2::Route', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'RouteKey': 'POST /revoke',
            'Target': {'Fn::Join': ['/', ['integrations', {'Ref': 'Integration'}]]}}},
        'FormRoute': {'Type': 'AWS::ApiGatewayV2::Route', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'RouteKey': 'GET /revoke',
            'Target': {'Fn::Join': ['/', ['integrations', {'Ref': 'Integration'}]]}}},
        'InvokePermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {
            'FunctionName': {'Ref': 'Public'}, 'Action': 'lambda:InvokeFunction',
            'Principal': 'apigateway.amazonaws.com',
            'SourceAccount': {'Ref': 'AWS::AccountId'},
            'SourceArn': {'Fn::Sub': 'arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*/*/revoke'}}},
    })
    delivery = Path(__file__).with_name('delivery.py').read_text()
    resources.update({
        'NoticeLedger': {'Type': 'AWS::DynamoDB::Table', 'DeletionPolicy': 'Retain',
            'UpdateReplacePolicy': 'Retain', 'Properties': {
                'BillingMode': 'PAY_PER_REQUEST', 'DeletionProtectionEnabled': True,
                'AttributeDefinitions': [{'AttributeName': 'id', 'AttributeType': 'S'}],
                'KeySchema': [{'AttributeName': 'id', 'KeyType': 'HASH'}],
                'SSESpecification': {'SSEEnabled': True},
                'PointInTimeRecoverySpecification': {'PointInTimeRecoveryEnabled': True},
                'OnDemandThroughput': {'MaxReadRequestUnits': 5, 'MaxWriteRequestUnits': 5}}},
        'NoticeDeadLetters': {'Type': 'AWS::SQS::Queue', 'Properties': {
            'SqsManagedSseEnabled': True, 'MessageRetentionPeriod': 1209600}},
        'NoticeQueue': {'Type': 'AWS::SQS::Queue', 'Properties': {
            'SqsManagedSseEnabled': True, 'MessageRetentionPeriod': 1209600,
            'VisibilityTimeout': 180,
            'RedrivePolicy': {'deadLetterTargetArn': {'Fn::GetAtt': ['NoticeDeadLetters', 'Arn']},
                             'maxReceiveCount': 5}}},
        'DeliveryRole': {'Type': 'AWS::IAM::Role', 'Properties': {
            'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]},
            'Policies': [{'PolicyName': 'delivery-only', 'PolicyDocument': {
                'Version': '2012-10-17', 'Statement': [
                    {'Effect': 'Allow', 'Action': ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'],
                     'Resource': {'Fn::GetAtt': ['NoticeQueue', 'Arn']}},
                    {'Effect': 'Allow', 'Action': ['dynamodb:GetItem'],
                     'Resource': {'Fn::GetAtt': ['NoticeLedger', 'Arn']}},
                    {'Effect': 'Allow', 'Action': ['dynamodb:UpdateItem'],
                     'Resource': {'Fn::GetAtt': ['NoticeLedger', 'Arn']},
                     'Condition': {'ForAllValues:StringLike': {'dynamodb:LeadingKeys': ['event#*']}}},
                    {'Effect': 'Allow', 'Action': ['ses:SendEmail'],
                     'Resource': [{'Fn::Sub': 'arn:${AWS::Partition}:ses:${AWS::Region}:${AWS::AccountId}:identity/openid.tensetti.io'},
                                  {'Fn::Sub': 'arn:${AWS::Partition}:ses:${AWS::Region}:${AWS::AccountId}:identity/${FeedbackAddress}'}],
                     'Condition': {'StringEquals': {'ses:FromAddress': 'avisering@openid.tensetti.io',
                                                    'ses:FeedbackAddress': {'Ref': 'FeedbackAddress'}}}}
                ]}}]}},
        'Delivery': {'Type': 'AWS::Lambda::Function', 'Properties': {
            'Runtime': 'python3.12', 'Handler': 'index.handler', 'MemorySize': 512,
            'Timeout': 20, 'ReservedConcurrentExecutions': 2,
            'Role': {'Fn::GetAtt': ['DeliveryRole', 'Arn']},
            'Environment': {'Variables': {'NOTICE_TABLE': {'Ref': 'NoticeLedger'},
                'NOTICE_QUEUE_ARN': {'Fn::GetAtt': ['NoticeQueue', 'Arn']},
                'NOTICE_FROM': 'avisering@openid.tensetti.io', 'NOTICE_FEEDBACK': {'Ref': 'FeedbackAddress'}}},
            'Code': {'ZipFile': delivery}}},
        'NoticeConsumer': {'Type': 'AWS::Lambda::EventSourceMapping', 'Properties': {
            'EventSourceArn': {'Fn::GetAtt': ['NoticeQueue', 'Arn']}, 'FunctionName': {'Ref': 'Delivery'},
            'BatchSize': 1, 'FunctionResponseTypes': ['ReportBatchItemFailures'],
            'ScalingConfig': {'MaximumConcurrency': 2}}},
    })
    for name in ('Backend', 'Public', 'Delivery'):
        resources[name]['Properties']['Layers'] = {'Fn::If': ['PinnedSdk', [{'Ref': 'SdkLayerArn'}], {'Ref': 'AWS::NoValue'}]}
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Parameters': {'TestBetaMode': {'Type': 'String', 'Default': 'disabled',
            'AllowedValues': ['disabled', 'testflight-november-2026'],
            'Description': 'Explicit test-only auto registration; every ledger ID revoked from 2026-11-30T23:00:00Z'},
            'SdkLayerArn': {'Type': 'String', 'Default': '',
            'AllowedPattern': r'^$|^arn:aws:lambda:eu-north-1:[0-9]{12}:layer:[A-Za-z0-9_-]+:[0-9]+$'},
            'FeedbackAddress': {'Type': 'String', 'NoEcho': True,
            'Description': 'Verified operator email for delivery failures; never a queue-supplied address'}},
        'Conditions': {'PinnedSdk': {'Fn::Not': [{'Fn::Equals': [{'Ref': 'SdkLayerArn'}, '']}]}},
        'Description': 'openID pilot isolated revocation authority; integration and migration required',
        'Resources': resources, 'Outputs': {
            'BackendFunction': {'Value': {'Ref': 'Backend'}},
            'LedgerTable': {'Value': {'Ref': 'Ledger'}},
            'NoticeTable': {'Value': {'Ref': 'NoticeLedger'}},
            'NoticeQueueUrl': {'Value': {'Ref': 'NoticeQueue'}},
            'NoticeQueueArn': {'Value': {'Fn::GetAtt': ['NoticeQueue', 'Arn']}},
            'RevokeEndpoint': {'Value': {'Fn::Sub': 'https://${Api}.execute-api.${AWS::Region}.${AWS::URLSuffix}/revoke'}}}}


if __name__ == '__main__': print(json.dumps(template()))
