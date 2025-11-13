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
    all_objects = s3_client.list_objects(
        Bucket=bucket['Name'])
    for obj in all_objects['Contents']:
        print(f'{obj}')
