#!/usr/bin/python3.11

import boto3

session = boto3.session.Session()

s3_client = session.client(
    service_name='s3',
    aws_access_key_id='aaa',
    aws_secret_access_key='bbb',
    endpoint_url='http://localhost:7878',
    verify=False,
    )

for bucket in s3_client.list_buckets():
    print(f'{bucket}')
