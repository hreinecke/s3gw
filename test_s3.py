#!/usr/bin/python3.11

import boto3
from botocore.config import Config

s3_config = Config(
    region_name = 'eu-west-2',
    signature_version = 'v4',
    )

session = boto3.session.Session()

s3_client = session.client(
    service_name = 's3',
    aws_access_key_id = 'aaa',
    aws_secret_access_key = 'bbb',
    config = s3_config,
    endpoint_url = 'http://localhost:7878')

all_buckets = s3_client.list_buckets(
        MaxBuckets=64,
        ContinuationToken='cont',
        Prefix='s3gw',
        BucketRegion='eu-west-2')
for bucket in all_buckets['Buckets']:
    print(f'{bucket}')
    head = s3_client.head_bucket(
        Bucket=bucket['Name'])
    print(f'Bucket: {head}')
    all_objects = s3_client.list_objects_v2(
        Bucket=bucket['Name'],
        MaxKeys=100,
        Prefix='server')
    print(f'{all_objects}')
    if 'Contents' in all_objects:
        for obj in all_objects['Contents']:
            print(f'{obj}')
            head = s3_client.head_object(
                Bucket=bucket['Name'],
                Key=obj['Key'])
            print(f'Object ETag: {head["ETag"]}')

try:
    resp = s3_client.create_bucket(
        Bucket='s3gw-test-bucket-1',
        CreateBucketConfiguration={
            'LocationConstraint': 'eu-west-2',
        },
    )
except Exception as e:
    resp = f'{e}'
    pass
print(f'{resp}')

with open('server-cert.pem') as fd:
    data = fd.read()

try:
    resp = s3_client.put_object(
        Body=f'{data}',
        Bucket='s3gw-test-bucket-1',
        Key='server-cert.pem',
        StorageClass='STANDARD_IA',
        )
except Exception as e:
    resp = f'{e}'
    pass
print(f'{resp}')

with open('server-cert.pem') as fd:
    data = fd.read()

try:
    resp = s3_client.get_object(
        Bucket='s3gw-test-bucket-1',
        Key='server-cert.pem',
        )
except Exception as e:
    resp = f'{e}'
    pass
print(f'{resp}')

try:
    resp = s3_client.copy_object(
        Bucket='s3gw-test-bucket-1',
        CopySource={
            'Bucket': 's3gw-test-bucket-1',
            'Key': 'server-cert.pem',
        },
        Key='server-cert-2.pem',
    )
except Exception as e:
    resp = f'{e}';
    pass
print(f'{resp}')

resp = s3_client.list_objects_v2(
    Bucket='s3gw-test-bucket-1',
    MaxKeys=100,
    Prefix='server')
print(f'{resp}')

try:
    resp = s3_client.delete_objects(
        Bucket='s3gw-test-bucket-1',
        Delete={
            'Objects': [
                {
                    'Key':'server-cert.pem',
                },
                {
                    'Key': 'server-cert-2.pem',
                }
            ]
        }
    )
except Exception as e:
    resp = f'{e}'
    pass
print(f'{resp}')

try:
    resp = s3_client.delete_bucket(
        Bucket='s3gw-test-bucket-1'
    )
except Exception as e:
    resp = f'{e}'
    pass
print(f'{resp}')

