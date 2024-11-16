from django.urls import path
from core.consumers import ChatConsumer

websocket_urlpatterns = [
    path('ws/room/<slug:room_slug>/', ChatConsumer.as_asgi()),
]