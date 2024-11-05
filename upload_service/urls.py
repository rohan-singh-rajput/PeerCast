from django.urls import path
from upload_service.views import UploadView
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from upload_service.views import UploadViewSet

router = DefaultRouter()
router.register(r'upload/chunk', UploadViewSet, basename='upload-chunk')

urlpatterns = [
    
    path('upload/', UploadView.as_view(), name='upload_page'),
    
   
]

