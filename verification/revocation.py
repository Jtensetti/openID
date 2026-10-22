"""Fail-closed, uncached access to the independent revocation authority.

The client is injected so the wallet does not own AWS credentials. A missing
record is not permission to authenticate. Only the operator may provision one.
"""
import json
import re


class RevocationUnavailable(ValueError):
    pass


class RevocationAuthority:
    def __init__(self, invoke):
        self.invoke = invoke

    def request(self, operation, credential):
        if not isinstance(credential, str) or not re.fullmatch('[a-f0-9]{64}', credential):
            raise ValueError('credential identifier')
        try:
            response = self.invoke({'operation': operation, 'credential': credential})
            if not isinstance(response, dict) or response.get('credential') != credential:
                raise ValueError('invalid authority response')
            state = response.get('state')
            if state not in {'ENABLED', 'REVOKED', 'UNKNOWN'}:
                raise ValueError('invalid authority state')
            return state
        except Exception:
            # Never expose provider response bodies, credentials or request tokens.
            raise RevocationUnavailable('revocation authority unavailable') from None

    def assert_allowed(self, credential):
        if self.request('status', credential) != 'ENABLED':
            raise ValueError('credential inactive at revocation authority')

    def revoke(self, credential):
        if self.request('revoke', credential) != 'REVOKED':
            raise RevocationUnavailable('revocation not confirmed')


def lambda_authority(client, function_name):
    """Use a least-privilege AWS SDK client, not a shared bearer admin secret."""
    def invoke(payload):
        result = client.invoke(FunctionName=function_name, InvocationType='RequestResponse',
                               Payload=json.dumps(payload).encode())
        if result.get('StatusCode') != 200 or result.get('FunctionError'):
            raise ValueError('authority invocation failed')
        raw = result['Payload'].read(4097)
        if len(raw) > 4096:
            raise ValueError('authority response size')
        return json.loads(raw)
    return RevocationAuthority(invoke)
