import boto3
from django.http import JsonResponse
from django.views import View
from django.conf import settings
from django.shortcuts import render
import uuid
import requests
from rest_framework.decorators import action
from rest_framework import viewsets


import logging
logger = logging.getLogger(__name__)



class UploadView(View):
    def get(self, request):
        return render(request, 'upload.html')
    
class UploadViewSet(viewsets.ViewSet):
    

    @action(detail=False, methods=['post'], url_path='presigned-url')
    def presigned_url(self, request):
        logger.debug(f"Received POST request: {request.POST}") 

        chunk = request.FILES.get('file')
        identifier = request.POST.get('resumableIdentifier')
        chunk_number = request.POST.get('resumableChunkNumber')

        if not chunk or not identifier or not chunk_number:
            return JsonResponse({'error': 'Invalid upload data'}, status=400)

        # filename for chunk
        filename = f"{identifier}/chunk_{chunk_number}_{uuid.uuid4()}"

        #  presigned URL 
        s3_client = boto3.client('s3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        try:
            presigned_url = s3_client.generate_presigned_url('put_object',
                Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': filename},
                ExpiresIn=3600
            )
        except Exception as e:
            return JsonResponse({'error': f'Failed to generate presigned URL: {str(e)}'}, status=500)

        # Upload chunk to S3
        try:
            response = requests.put(presigned_url, data=chunk)
            if response.status_code != 200:
                return JsonResponse({'error': 'Failed to upload chunk'}, status=response.status_code)
        except Exception as e:
            return JsonResponse({'error': f'Failed to upload chunk: {str(e)}'}, status=500)

        return JsonResponse({'message': 'Chunk uploaded successfully', 'url': presigned_url})

