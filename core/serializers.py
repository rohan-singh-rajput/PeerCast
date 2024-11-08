from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Room, Participant

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = ('room_id', 'room_name', 'is_private', 'join_code', 'max_participants', 'party_mode', 'sync_time')

class ParticipantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Participant
        fields = ('user', 'joined_at')
