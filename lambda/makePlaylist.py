import json
import boto3
from boto3.dynamodb.conditions import Key, Attr
import os
import math
import logging
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize S3 and DynamoDB clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
metadata_db = dynamodb.Table('metadata_db')
output_bucket_name = 'output-hls-bucket'

# Mapping resolution numbers to their names
resolution_map = {
    '1': 'highest',
    '2': 'high',
    '3': 'standard',
    '4': 'low'
}

def lambda_handler(event, context):
    """ 
    Lambda function to update HLS playlist for a video based on processed chunks.

    Parameters:
    event: dict - Input parameters including video_name, endlist_flag, and index.
    context: object - Runtime information for the Lambda function.

    Returns:
    dict - Response containing status code, message, endlist_flag, video_name, and updated index.
    """
    
    # Retrieve input parameters from the event
    video_name = event['video_name']
    endlist_flag = event['endlist_flag']
    index = event['index']

    try:
        response = metadata_db.query(
            KeyConditionExpression=Key('video_name').eq(video_name),
            FilterExpression=Attr('is_added').eq(False) & Attr('url').exists()
        )

        items = response.get('Items', [])
    except ClientError as e:
        logger.error("An error occurred while fetching items: %s", e.response['Error']['Message'])
        return []

    logger.info(f"Got {len(items)} from DB!")

    chunks_available = dict()
    chunk_info = dict()  # Nested dictionary storing chunk information for resolution

    """ 
    Process the fetched items to determine available chunks and their resolutions.
    """
    for item in items:
        chunkno_reso = item['chunkno_reso']
        chunkno = chunkno_reso[:-1]  
        reso = chunkno_reso[-1]      

        if reso != '9':
            
            if chunkno not in chunks_available:
                chunks_available[chunkno] = 1
            else:
                chunks_available[chunkno] += 1

            
            if chunkno not in chunk_info:
                chunk_info[chunkno] = {reso: item}
            else:
                chunk_info[chunkno][reso] = item
        else:
            chunks_available[chunkno] = 4
            chunk_info[chunkno] = 9

    # Set of chunk numbers which are fully processed
    sorted_list = sorted(list(int(i) for i in chunks_available.keys() if chunks_available[i] == 4))
    consecutive_chunks = []

    
    for chunk_no in sorted_list:
        if chunk_no == index:
            consecutive_chunks.append(chunk_no)
            index += 1

            if chunk_info[str(chunk_no)] == 9:
                endlist_flag = True
                logger.info(f"endlist_flag set to: {endlist_flag}")
        else:
            break

    logger.info(f"{consecutive_chunks} consecutive chunks are present!")

    # Construct the M3U8 playlist with the selected chunks
    construct_m3u8(video_name, consecutive_chunks, chunk_info, output_bucket_name, endlist_flag)

    
    for chunk_no in consecutive_chunks:
        if chunk_info[str(chunk_no)] != 9:
            for reso in ('1', '2', '3', '4'):
                chunkno_reso = chunk_info[str(chunk_no)][reso]['chunkno_reso']
                logger.info(f"chunkno_reso: {chunkno_reso}")
                update_is_added(video_name, chunkno_reso)
        else:
            update_is_added(video_name, str(chunk_no) + '9')

    return {
        'statusCode': 200,
        'body': json.dumps('Playlist successfully UPDATED!'),
        'endlist_flag': endlist_flag,
        'video_name': video_name,
        'index': index
    }

def construct_m3u8(video_name, consecutive_chunks, chunk_info, output_bucket_name, endlist_flag):
    """ 
    Construct M3U8 playlist files for the video and upload to S3.

    Parameters:
    video_name: str - Name of the video for which playlists are created.
    consecutive_chunks: list - List of consecutive chunks to include in the playlist.
    chunk_info: dict - Information about the chunks and their resolutions.
    output_bucket_name: str - S3 bucket name where playlists will be uploaded.
    endlist_flag: bool - Flag indicating whether to append the ENDLIST tag.
    """
    
    output_folder_path = f'{video_name}/playlist/'
    local_output_dir = f"/tmp/{output_folder_path}"
    os.makedirs(local_output_dir, exist_ok=True)

    reso_map = {
        '1': 'highest',
        '2': 'high',
        '3': 'standard',
        '4': 'low'
    }

    for i in ('1', '2', '3', '4'):
        output_folder_path = f'{video_name}/playlist/'
        playlist_key = f'{output_folder_path}{reso_map[i]}.m3u8'
        local_playlist_path = os.path.join(local_output_dir, f"{reso_map[i]}.m3u8")

        try:
            # Check if the playlist exists in S3
            s3.head_object(Bucket=output_bucket_name, Key=playlist_key)
            download_path = os.path.join(local_output_dir, "playlist.m3u8")
            s3.download_file(output_bucket_name, playlist_key, download_path)

            with open(download_path, 'r') as file:
                existing_content = file.read()
                new_content = []
                for chunk in consecutive_chunks:
                    if chunk == consecutive_chunks[-1] and endlist_flag:
                        new_content.append(f'#EXT-X-ENDLIST\n')
                        logger.info('#EXT-X-ENDLIST appended')
                    else:
                        url = chunk_info[str(chunk)][i]['url']
                        duration = float(chunk_info[str(chunk)][i]['duration'])
                        new_content.append(f"#EXTINF:{duration:.6f},\n{url}\n")
                        logger.info(f"M3U8 playlist with chunk no {chunk} has been updated successfully.")
                
                combined_content = existing_content + str(''.join(new_content))
                logger.debug(f"Combined content: {combined_content}")

            # Upload the updated playlist back to S3
            upload_to_s3(combined_content, output_bucket_name, playlist_key)
            logger.info(f"files Uploaded for reso {reso_map[i]}!")
        
        except IOError as e:
            logger.error("Failed to write M3U8 file: %s", e)
            return ""

    logger.info("All playlist files updated!")

def upload_to_s3(content, bucket_name, key):
    """ 
    Upload content to S3.

    Parameters:
    content: str - Content to upload to S3.
    bucket_name: str - Name of the S3 bucket.
    key: str - Key (path) where the content will be stored.
    """
    try:
        s3.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=content,
            ContentType="application/vnd.apple.mpegurl"
        )
        logger.info(f"Successfully uploaded {key} to S3.")

    except ClientError as e:
        logger.error("Failed to upload to S3: %s", e.response['Error']['Message'])

def update_is_added(video_name, chunkno_reso):
    """ 
    Update the database to mark a chunk as added.

    Parameters:
    video_name: str - Name of the video.
    chunkno_reso: str - Chunk number and resolution identifier.
    """
    try:
        metadata_db.update_item(
            Key={
                'video_name': video_name,
                'chunkno_reso': chunkno_reso
            },
            UpdateExpression="SET is_added = :val",
            ExpressionAttributeValues={
                ':val': True
            }
        )
        logger.info(f"Updated is_added to True for chunkno_reso: {chunkno_reso} in video: {video_name}")

    except ClientError as e:
        logger.error(f"Failed to update is_added for {chunkno_reso}: %s", e.response['Error']['Message'])
