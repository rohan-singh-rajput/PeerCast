from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    # home
    path('', views.home_view,name='home'),

    # auth
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    #  dashboard
    path('dashboard/',views.dashboard_view,name='dashboard'),

    # room
    # Room Management
    path('rooms/', views.room_list_view, name='room_list'),            # List all rooms
    path('rooms/create/', views.create_room_view, name='create_room'), # Create a new room
    path('rooms/<slug:slug>/', views.room_detail_view, name='room_detail'), # Room detail (video + chat)
    path('room/demo',views.demo_room,name="demo_room"),

    path('get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),
    path('invoke_step_function/', views.start_step_function, name='invoke_step_function'),
    path('invoke_endlist/', views.update_endlist_db, name='invoke_endlist'),
    path('uploads/', views.upload_view, name='upload_view'),
    

   path('join/<slug:slug>/', views.join_room_view, name='join_room'),
   path('join-room-link/', views.join_room_via_link, name='join_room_via_link'),
   path('room/<slug:slug>/close/', views.close_room, name='close_room'),

   path('webauthn/register/start/', views.webauthn_register_start, name='webauthn_register_start'),
   path('webauthn/register/complete/', views.webauthn_register_complete, name='webauthn_register_complete'),
   path('webauthn/login/start/', views.webauthn_login_start, name='webauthn_login_start'),
   path('webauthn/login/complete/', views.webauthn_login_complete, name='webauthn_login_complete'),
    
]