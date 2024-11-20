import boto3
import time
import json
import urllib.parse
import os

lambda_client = boto3.client('lambda')

def lambda_handler(event, context):
    '''
    Handles S3 event notifications and invoke transcoding Lambda function

    Parameters:
    event: dict - Contains S3 event details, including bucket name and object key.
    context: object - Runtime information for the Lambda function.
    '''
    
    # Extract details from event
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    input_key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])
    input_filename = os.path.basename(input_key)
    chunk_number = int(input_filename.split('_')[1][:4])
    video_name = input_filename.split('_')[0]

    lambda_arn = os.environ['LAMBDA_ARN']

    # Quality - 'highest': '1', 'high': '2', 'standard': '3', 'low': '4'
    for res in ('1', '2', '3', '4'):
        payload = {
            "bucket_name": bucket_name,
            "chunk_number": chunk_number,
            "video_name": video_name,
            "resolution": res
            }
    
        payload_json = json.dumps(payload)
        payload_encoded = payload_json.encode('utf-8')
        
        # Invoke lambda for transcoding
        response_highest = lambda_client.invoke(
            FunctionName = lambda_arn,
            InvocationType = 'Event',  
            Payload = payload_encoded  
        )
    
