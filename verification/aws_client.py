"""Fixed, verified TLS destinations for the three runtime AWS services."""
ENDPOINTS = {
    'lambda': 'https://lambda.eu-north-1.amazonaws.com',
    'sqs': 'https://sqs.eu-north-1.amazonaws.com',
    'dynamodb': 'https://dynamodb.eu-north-1.amazonaws.com',
}


def runtime_client(service, *, read_timeout):
    import boto3
    from botocore.config import Config
    import os
    import shlex
    import sys
    from pathlib import Path
    session_file = os.environ.get('OPENID_AWS_SESSION_FILE')
    factory = boto3
    if session_file is not None:
        import botocore.session
        from botocore.credentials import CredentialResolver, ProcessProvider
        if session_file != '/srv/openid/aws/session.json':
            raise ValueError('fixed per-service session path required')
        command = shlex.join([sys.executable, str(Path(__file__).with_name('aws_credential_process.py')), session_file])
        provider = ProcessProvider('tjipp', load_config=lambda: {'profiles': {'tjipp': {'credential_process': command}}})
        session = botocore.session.get_session()
        session.register_component('credential_provider', CredentialResolver([provider]))
        factory = boto3.Session(botocore_session=session)
    return factory.client(service, region_name='eu-north-1', endpoint_url=ENDPOINTS[service],
        config=Config(connect_timeout=2, read_timeout=read_timeout,
                      retries={'total_max_attempts': 1}, proxies={}))
