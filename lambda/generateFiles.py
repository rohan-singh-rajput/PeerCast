import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize S3 client
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    """ 
    Lambda function to create and upload HLS playlist files to S3.
    
    Parameters:
    event: dict - Input parameters including video_name and output_bucket_name.
    context: object - Runtime information for the Lambda function.
    
    Returns:
    dict - Response containing status code and message.
    """
    
    # Retrieve input parameters
    video_name = event.get('video_name')
    output_bucket_name = event.get('output_bucket_name')
    
    if not video_name or not output_bucket_name:
        logger.error('Missing required parameters: video_name or output_bucket_name')
        return {
            'statusCode': 400,
            'body': json.dumps('Error: Missing video_name or output_bucket_name in the event.')
        }
    
    logger.info(f'Processing video: {video_name} for bucket: {output_bucket_name}')
    
    # Quality levels with their attributes
    qualities = [
        {'name': 'highest', 'bandwidth': 2500000, 'resolution': '1920x1080'},
        {'name': 'high', 'bandwidth': 1500000, 'resolution': '1280x720'},
        {'name': 'standard', 'bandwidth': 800000, 'resolution': '854x480'},
        {'name': 'low', 'bandwidth': 600000, 'resolution': '640x360'}
    ]
    
    """ 
    Create and upload individual playlist.m3u8 files for each quality level.
    """
    for quality in qualities:
        # Headers for a playlist file
        playlist_content = '#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-PLAYLIST-TYPE:EVENT\n#EXT-X-START:TIME-OFFSET=0.0,PRECISE=YES\n#EXT-X-TARGETDURATION:5\n#EXT-X-MEDIA-SEQUENCE:0\n'
        
        # S3 key for the playlist
        key = f"{video_name}/playlist/{quality['name']}.m3u8"
        
        try:
            logger.info(f"Uploading playlist for quality: {quality['name']}")
            s3_client.put_object(
                Bucket=output_bucket_name,
                Key=key,
                Body=playlist_content,
                ContentType='application/vnd.apple.mpegurl'
            )
        except Exception as e:
            logger.error(f"Error uploading {key} to S3: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps(f"Error uploading {key} to S3: {str(e)}")
            }
    
    """ 
    Create the master.m3u8 file content which references all individual playlists.
    """
    logger.info('Creating master playlist file')
    master_playlist_content = '#EXTM3U\n'
    for quality in qualities:
        master_playlist_content += (
            f"#EXT-X-STREAM-INF:BANDWIDTH={quality['bandwidth']},"
            f"RESOLUTION={quality['resolution']}," 
            f"CODECS=\"avc1.64001e,mp4a.40.2\"\n"
            f"https://{output_bucket_name}.s3.ap-south-1.amazonaws.com/{video_name}/playlist/{quality['name']}.m3u8\n"
        )
    
    # S3 key for the master playlist
    master_key = f"{video_name}/master.m3u8"
    
    try:
        logger.info('Uploading master playlist file')
        s3_client.put_object(
            Bucket=output_bucket_name,
            Key=master_key,
            Body=master_playlist_content,
            ContentType='application/vnd.apple.mpegurl'
        )
    except Exception as e:
        logger.error(f"Error uploading master.m3u8 to S3: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error uploading master.m3u8 to S3: {str(e)}")
        }
    
    logger.info('Successfully created and uploaded all playlist files')
    return {
        'statusCode': 200,
        'body': json.dumps('Playlist files successfully created and uploaded to S3.')
    }
