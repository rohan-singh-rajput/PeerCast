from celery import shared_task
import boto3
from django.conf import settings
from .models import Room

@shared_task
def update_room_with_hls_url(room_id, s3_key):
    """
    Update the Room model with the HLS playlist URL after processing.
    """
    s3 = boto3.client('s3', region_name=settings.AWS_S3_REGION_NAME)
    room = Room.objects.get(id=room_id)
    
    # Construct HLS URL (assuming it's uploaded to a 'processed/' folder in S3)
    hls_url = f"https://{settings.AWS_CLOUDFRONT_DOMAIN}/output-hls-bucket/{s3_key}/hls/playlist.m3u8"
    
    # Update room with the video URL
    room.video_url = hls_url
    room.save()
