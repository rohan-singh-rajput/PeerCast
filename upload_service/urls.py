from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_view, name='upload_view'),
    path('get_presigned_url/', views.get_presigned_url, name='get_presigned_url'),
    path('invoke_step_function/', views.start_step_function, name='invoke_step_function'),
    path('invoke_endlist/', views.update_endlist_db, name='invoke_endlist'),
]