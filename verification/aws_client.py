"""Fixed, verified TLS destinations for the three runtime AWS services."""
ENDPOINTS = {
    'lambda': 'https://lambda.eu-north-1.amazonaws.com',
    'sqs': 'https://sqs.eu-north-1.amazonaws.com',
    'dynamodb': 'https://dynamodb.eu-north-1.amazonaws.com',
}


def runtime_client(service, *, read_timeout):
    import boto3
    from botocore.config import Config
    return boto3.client(service, region_name='eu-north-1', endpoint_url=ENDPOINTS[service],
        config=Config(connect_timeout=2, read_timeout=read_timeout,
                      retries={'total_max_attempts': 1}, proxies={}))
