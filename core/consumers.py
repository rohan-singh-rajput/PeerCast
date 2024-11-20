import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import Room, Message

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_slug']
        self.room_group_name = f'chat_{self.room_name}'

        # Verify user is authenticated and has access to the room
        if self.scope["user"].is_anonymous:
            await self.close()
            return
            
        # Verify room exists and user has access
        try:
            room = await self.get_room()
            if not await self.user_has_access(room):
                await self.close()
                return
        except Room.DoesNotExist:
            await self.close()
            return

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

        # Send message history to newly connected client
        messages = await self.get_messages()
        await self.send(text_data=json.dumps({
            'type': 'history',
            'messages': messages
        }))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json['message']
            user = self.scope['user']
            
            # Save message to database
            saved_message = await self.save_message(user, message)

            # Send message to room group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message,
                    'username': user.username,
                    'timestamp': saved_message.timestamp.isoformat()
                }
            )
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'error': 'Invalid message format'
            }))

    async def chat_message(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'username': event['username'],
            'timestamp': event['timestamp']
        }))

    @database_sync_to_async
    def get_room(self):
        return Room.objects.get(slug=self.room_name)

    @database_sync_to_async
    def user_has_access(self, room):
        return (
            self.scope["user"] == room.owner or 
            self.scope["user"] in room.participants.all()
        )

    @database_sync_to_async
    def save_message(self, user, message):
        room = Room.objects.get(slug=self.room_name)
        return Message.objects.create(
            room=room,
            user=user,
            content=message
        )

    @database_sync_to_async
    def get_messages(self):
        room = Room.objects.get(slug=self.room_name)
        messages = Message.objects.filter(room=room).select_related('user')
        return [
            {
                'message': msg.content,
                'username': msg.user.username,
                'timestamp': msg.timestamp.isoformat()
            }
            for msg in messages
        ]

    
