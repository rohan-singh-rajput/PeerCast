from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.URLField(blank=True, null=True)


class Room(models.Model):
    room_id = models.UUIDField(primary_key=True, unique=True, editable=False)
    room_name = models.CharField(max_length=100)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_rooms")
    is_private = models.BooleanField(default=False)
    join_code = models.CharField(max_length=6, blank=True, null=True)
    max_participants = models.IntegerField(default=10)
    party_mode = models.BooleanField(default=False)
    sync_time = models.DateTimeField(blank=True, null=True)


class Participant(models.Model):
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name="participants")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)
