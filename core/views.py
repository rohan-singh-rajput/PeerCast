from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Room, Participant
from .serializers import RoomSerializer, ParticipantSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.settings import api_settings
import uuid
from django.contrib.auth.models import User

class RegisterView(APIView):
    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        user = User.objects.create_user(username=username, email=email, password=password)
        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)

class CreateRoomView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        room_data = {
            "room_id": uuid.uuid4(),
            "room_name": request.data.get("room_name"),
            "creator": request.user.id,
            "is_private": request.data.get("is_private"),
            "join_code": request.data.get("join_code") if request.data.get("is_private") else None,
            "max_participants": request.data.get("max_participants", 10),
        }
        room_serializer = RoomSerializer(data=room_data)
        if room_serializer.is_valid():
            room_serializer.save()
            return Response(room_serializer.data, status=status.HTTP_201_CREATED)
        return Response(room_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JoinRoomView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        room_id = request.data.get("room_id")
        join_code = request.data.get("join_code")
        try:
            room = Room.objects.get(room_id=room_id)
            if room.is_private and room.join_code != join_code:
                return Response({"error": "Invalid join code"}, status=status.HTTP_403_FORBIDDEN)
            participant, created = Participant.objects.get_or_create(room=room, user=request.user)
            return Response({"message": "Joined room successfully"}, status=status.HTTP_200_OK)
        except Room.DoesNotExist:
            return Response({"error": "Room not found"}, status=status.HTTP_404_NOT_FOUND)

class PartyModeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, room_id):
        try:
            # Only allow the creator to control party mode
            room = Room.objects.get(room_id=room_id, creator=request.user)
            room.party_mode = request.data.get("enable")
            room.sync_time = request.data.get("sync_time")
            room.save()
            return Response({"party_mode": room.party_mode, "sync_time": room.sync_time}, status=status.HTTP_200_OK)
        except Room.DoesNotExist:
            return Response({"error": "Only the room creator can control party mode."},
                            status=status.HTTP_403_FORBIDDEN)

