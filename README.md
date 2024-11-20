# PeerCast  

PeerCast is a real-time video streaming application that enables private room creation, live video synchronization, and a dynamic chat experience. The platform supports video chunk uploads to AWS S3, transcoding for adaptive streaming, and seamless video playback with room-based controls.

---

## Features  

- **Private Rooms**: Users can create private rooms for video streaming with chat functionality.  
- **Live Video Playback**: Video streaming is synchronized for all participants, with playback control restricted to the room owner.  
- **Chat Integration**: Scalable chat functionality for real-time communication among room members.  
- **Video Upload & Processing**: Videos are chunk-uploaded to AWS S3 and transcoded to adaptive streaming format (HLS).  
- **Authentication**: Secure user authentication with Django and PostgreSQL.  
- **Scalable Architecture**: Hosted on AWS with EC2 instances, S3 for storage, and Lambda for transcoding automation.

---

## High-Level Design  

### Architecture  

- **Frontend**: Django Templates  
- **Backend**: Django-based APIs with WebSocket support for real-time communication  
- **Database**: PostgreSQL for user data and room details  
- **Storage**: AWS S3 for video file storage  
- **Transcoding**: AWS Lambda for video processing into HLS/DASH formats  
- **Chat Service**: Websocket and redis for scalability
- **Hosting**: AWS EC2 instances  

### Workflow  

1. **Authentication**: Users log in or register.  
2. **Room Management**:  
   - Create or join a private room.  
3. **Video Upload**: Users upload videos, which are chunked and uploaded to S3.  
4. **Video Processing**: Lambda functions transcode videos into adaptive streaming formats.  
5. **Video Playback**: Videos are streamed in real-time using HLS protocol.  
6. **Chat**: Real-time chat feature with Redis and WebSocket communication.  

