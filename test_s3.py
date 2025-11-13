#!/usr/bin/python3.11

import boto3

session = boto3.session.Session()

s3_client = session.client(
    service_name='s3',
    aws_access_key_id='aaa',
    aws_secret_access_key='bbb',
    endpoint_url='http://localhost:7878')

all_buckets = s3_client.list_buckets(
        MaxBuckets=100,
        ContinuationToken='cont',
        Prefix='',
        BucketRegion='eu-west-2')
for bucket in all_buckets['Buckets']:
    print(f'{bucket}')
    head = s3_client.head_bucket(
        Bucket=bucket['Name'])
    print(f'Bucket: {head}')
    all_objects = s3_client.list_objects(
        Bucket=bucket['Name'],
        MaxKeys=100,
        Prefix='server')
    for obj in all_objects['Contents']:
        print(f'{obj}')
        head = s3_client.head_object(
            Bucket=bucket['Name'],
            Key=obj['Key'])
        print(f'Object: {head}')
