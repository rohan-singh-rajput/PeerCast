from django.urls import path
from .views import RegisterView, CreateRoomView, JoinRoomView, PartyModeView

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('rooms/create/', CreateRoomView.as_view(), name='create_room'),
    path('rooms/join/', JoinRoomView.as_view(), name='join_room'),
    path('rooms/<uuid:room_id>/party-mode/', PartyModeView.as_view(), name='party_mode'),
    # path('rooms/<uuid:room_id>/upload-video/', VideoUploadView.as_view(), name='upload_video'),
]
