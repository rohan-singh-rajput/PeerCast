import json
import boto3
import subprocess
import os
import urllib.parse
import re
import shutil
import time
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Initialize AWS clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
metadata_db = dynamodb.Table('metadata_db')

def lambda_handler(event, context):
    """ 
    Lambda function to process video chunks, transcode and upload to S3.

    Parameters:
    event: dict - Input parameters including bucket_name, chunk_number, video_name, and resolution.
    context: object - Runtime information for the Lambda function.

    Returns:
    dict - Response containing status code and message about processing status.
    """
    
    bucket_name = event['bucket_name']
    chunk_number = int(event['chunk_number'])
    video_name = event['video_name']
    quality_no = event['resolution']
    
    logger.info("Transcoder RUNNING")

    # File location inside the S3 bucket
    input_key = f"{video_name}/{video_name}_{chunk_number:04d}.ts"

    output_bucket_name = 'output-hls-bucket'
    
    # Mapping resolution numbers to attributes
    resolution = {
        '4': {'name': 'low',       'width': 640,   'bitrate': '350k'},
        '3': {'name': 'standard',  'width': 854,   'bitrate': '500k'},
        '2': {'name': 'high',      'width': 1280,  'bitrate': '1000k'},
        '1': {'name': 'highest',   'width': 1920,  'bitrate': '1700k'},   
    }

    # Output folder path for the selected quality
    output_folder_path = f'{video_name}/{resolution[quality_no]["name"]}/'

    # Download the uploaded chunk to /tmp/{video_name}_{chunk_number}.mp4
    input_filename = os.path.basename(input_key)
      
    download_path = f'/tmp/{input_filename}'
    s3.download_file(bucket_name, input_key, download_path)
    
    # Transcode the video chunk
    transcode_chunk(output_bucket_name, download_path, output_folder_path, resolution[quality_no], chunk_number, video_name)

    # Generate URL for the output segment
    url = f'https://{output_bucket_name}.s3.ap-south-1.amazonaws.com/{output_folder_path}segment_{chunk_number:04d}.ts'

    # Duration of the processed segment
    duration = get_duration(download_path, output_folder_path, chunk_number)

    # Store video metadata in the database
    if duration:
        upload_status_to_db(video_name, str(chunk_number) + quality_no, url, f"{duration:.6f}")
    else:
        raise ValueError(f"Failed to retrieve duration for chunk {chunk_number} of video {video_name}.")
 
    return {
        'statusCode': 200,
        'body': 'Chunk processed successfully'
    }

def get_duration(download_path, output_folder_path, chunk_number):
    """ 
    Retrieve the duration of the video segment using ffprobe.

    Parameters:
    download_path: str - Path to the downloaded video segment.
    output_folder_path: str - Output folder path for storing the segment.
    chunk_number: int - The chunk number of the video.

    Returns:
    float or None - Duration of the video segment in seconds or None if failed.
    """
    
    local_output_folder = f"/tmp/{output_folder_path}"
    os.makedirs(local_output_folder, exist_ok=True)

    # ffprobe command
    cmd = [
        'ffprobe',
        '-v', 'error',                # Suppress unnecessary output
        '-show_entries', 'format=duration',  # Extract duration
        '-of', 'json',                # Output format as JSON
        f"{local_output_folder}segment_{chunk_number:04d}.ts"
    ]

    try:
        # Execute the command
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for errors
        if result.returncode != 0:
            raise RuntimeError(f"ffprobe error: {result.stderr.strip()}")

        # Parse the JSON output
        info = json.loads(result.stdout)

        # Extract and return the duration
        duration = float(info['format']['duration'])
        return duration

    except Exception as e:
        logger.error(f"An error occurred while retrieving duration: {e}")
        return None

def transcode_chunk(output_bucket_name, download_path, output_folder_path, res, chunk_number, video_name):
    """ 
    Transcode a video chunk using ffmpeg and upload the output to S3.

    Parameters:
    output_bucket_name: str - Name of the S3 bucket for output.
    download_path: str - Local path of the downloaded chunk.
    output_folder_path: str - S3 folder path for the output segment.
    res: dict - Resolution attributes including bitrate and width.
    chunk_number: int - The number of the chunk being processed.
    video_name: str - The name of the video.
    """
   
    local_output_folder = f"/tmp/{output_folder_path}"
    os.makedirs(local_output_folder, exist_ok=True)

    # Build the ffmpeg command for transcoding
    command = [
        'ffmpeg', '-y',
        '-copyts',
        '-i', download_path,
        '-c:v', 'libx264',
        '-preset', 'veryfast',
        '-b:v', res['bitrate'],
        '-vf', f"scale={res['width']}:-1",
        '-c:a', 'aac',
        '-b:a', '128k',
        '-force_key_frames', 'expr:gte(t,n_forced*5)',
        '-f', 'hls',
        '-hls_time', '6',
        '-hls_flags', 'independent_segments+append_list',
        '-hls_list_size', '0',
        '-start_number', f'{chunk_number:04d}',
        '-hls_base_url', f'https://{output_bucket_name}.s3.ap-south-1.amazonaws.com/{video_name}/{res["name"]}/',
        '-hls_segment_filename', f"{local_output_folder}segment_%04d.ts",
        f"{local_output_folder}playlist_{chunk_number}.m3u8"
    ]

    try:
        # Execute the ffmpeg command
        subprocess.run(command, check=True)
        # Upload the output folder to S3
        upload_folder_to_s3(local_output_folder, output_bucket_name, output_folder_path)

    except subprocess.CalledProcessError as e:
        logger.error(f"An error occurred during conversion: {e}")

def upload_status_to_db(video_name, chunkno_reso, url, duration):
    """ 
    Upload video chunk metadata to DynamoDB.

    Parameters:
    video_name: str - Name of the video.
    chunkno_reso: str - Chunk number and resolution identifier.
    url: str - URL of the processed chunk.
    duration: str - Duration of the chunk in seconds.
    """
    try:
        response = metadata_db.put_item(
            Item={
                'video_name': video_name,
                'chunkno_reso': chunkno_reso,
                'url': url,
                'is_added': False,
                'duration': Decimal(duration)
            }
        )
    except ClientError as e:
        logger.error("Failed to insert item:", e.response['Error']['Message'])

def upload_folder_to_s3(folder_path, output_bucket_name, s3_prefix):
    """ 
    Upload the output folder to S3.

    Parameters:
    folder_path: str - Local path to the folder to upload.
    output_bucket_name: str - Name of the S3 bucket.
    s3_prefix: str - S3 prefix or folder path where files will be uploaded.
    """
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            local_path = os.path.join(root, file)
            relative_path = os.path.relpath(local_path, folder_path)
            s3_key = f"{s3_prefix}{relative_path}"
            s3.upload_file(local_path, output_bucket_name, s3_key)
