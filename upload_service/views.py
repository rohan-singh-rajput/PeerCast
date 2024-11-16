import boto3
import os
import json
from dotenv import load_dotenv
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
import uuid
from botocore.exceptions import ClientError

# Create your views here.

load_dotenv()

s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],
    aws_secret_access_key=os.environ['SECRET_KEY_AWS'],
    region_name=os.environ['REGION_AWS']
)

        
# Initialize Step Functions client
step_client = boto3.client(
    'stepfunctions',
    region_name=os.environ['REGION_AWS'],
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
    aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.environ['REGION_AWS'],
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
    aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles)
)

metadata_db = dynamodb.Table('metadata_db')

def upload_view(request):
    return render(request, 'upload_file.html')


@csrf_exempt
def get_presigned_url(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        filename = data.get('filename')
        videoName = filename[:-4]
        extension = 'ts'

        chunk_number = data.get('chunkNumber')

        #Generate the chunk filename with chunk number
        chunk_filename = f"{videoName}_{chunk_number:04d}.{extension}"

        # Generate a presigned URL for this chunk
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': os.environ['BUCKET_NAME'],
                'Key': f"{videoName}/{chunk_filename}",
                'ContentType': 'video/mp2t'
            },
            ExpiresIn=180
        )

        return JsonResponse({'presigned_url': presigned_url})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt  # Use appropriate authentication in production
def start_step_function(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    
    try:
        # Parse JSON body
        data = json.loads(request.body)
        filename = data.get('filename')
        video_name = filename[:-4]
        output_bucket_name = 'output-hls-bucket'
        
        if not video_name:
            return JsonResponse({'error': 'Missing video_name.'}, status=400)
        
        # Prepare input for Step Functions
        input_payload = {
            'video_name': video_name,
            'output_bucket_name': output_bucket_name
        }
        
        # Start Step Function execution
        response = step_client.start_execution(
            stateMachineArn=os.environ['STATE_MACHINE_ARN'],
            input=json.dumps(input_payload),
            name=f"{video_name}_execution_{uuid.uuid4()}"  # Optional: Provide a unique name
        )
        
        return JsonResponse({
            'message': 'Step Function execution started successfully.',
            'executionArn': response.get('executionArn'),
            'startDate': response.get('startDate').isoformat()
        }, status=200)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    except step_client.exceptions.ExecutionAlreadyExists:
        return JsonResponse({'error': 'An execution with the same name already exists.'}, status=409)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

@csrf_exempt
def update_endlist_db(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    try:
        data = json.loads(request.body)
        filename = data.get('filename')
        video_name = filename[:-4]
        response = metadata_db.put_item(
            Item={
                'video_name': video_name,
                'chunkno_reso': '99999',
                'url': 'ENDLIST',
                'is_added': False
            }
        )
        print("Insert successful:", response)

        return JsonResponse({'message': 'Insert successful.'}, status=200)
            
    except ClientError as e:
        # Log the error message
        print("Failed to insert item:", e.response['Error']['Message'])
        
        # Return an error response
        return JsonResponse({'error': 'Failed to insert item into the database.'}, status=500)
    
    except json.JSONDecodeError:
        # Handle invalid JSON
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    
    except Exception as e:
        # Catch-all for any other exceptions
        print("An unexpected error occurred:", str(e))
        return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)