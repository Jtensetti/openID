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
            'Runtime': 'python3.12', 'Handler': 'index.'+handler, 'MemorySize': 128,
            'Timeout': 8, 'ReservedConcurrentExecutions': 2,
            'Role': {'Fn::GetAtt': [name+'Role', 'Arn']},
            'Environment': {'Variables': {'REVOCATION_TABLE': {'Ref': 'Ledger'}}},
            'Code': {'ZipFile': code}}}
    resources.update({
        'Integration': {'Type': 'AWS::ApiGatewayV2::Integration', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'IntegrationType': 'AWS_PROXY',
            'IntegrationUri': {'Fn::GetAtt': ['Public', 'Arn']}, 'PayloadFormatVersion': '2.0',
            'TimeoutInMillis': 10000}},
        'Route': {'Type': 'AWS::ApiGatewayV2::Route', 'Properties': {
            'ApiId': {'Ref': 'Api'}, 'RouteKey': 'POST /revoke',
            'Target': {'Fn::Join': ['/', ['integrations', {'Ref': 'Integration'}]]}}},
        'InvokePermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {
            'FunctionName': {'Ref': 'Public'}, 'Action': 'lambda:InvokeFunction',
            'Principal': 'apigateway.amazonaws.com',
            'SourceAccount': {'Ref': 'AWS::AccountId'},
            'SourceArn': {'Fn::Sub': 'arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*/POST/revoke'}}},
    })
    return {'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'openID pilot isolated revocation authority; integration and migration required',
        'Resources': resources, 'Outputs': {
            'BackendFunction': {'Value': {'Ref': 'Backend'}},
            'LedgerTable': {'Value': {'Ref': 'Ledger'}},
            'RevokeEndpoint': {'Value': {'Fn::Sub': 'https://${Api}.execute-api.${AWS::Region}.${AWS::URLSuffix}/revoke'}}}}


if __name__ == '__main__': print(json.dumps(template()))
