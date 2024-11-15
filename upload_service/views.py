import boto3
import os
import json
from dotenv import load_dotenv
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

# Create your views here.

load_dotenv()

s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],
    aws_secret_access_key=os.environ['SECRET_KEY_AWS'],
    region_name=os.environ['REGION_AWS']
)


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