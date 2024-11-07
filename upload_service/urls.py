from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_view, name='upload_view'),
    path('get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),
]