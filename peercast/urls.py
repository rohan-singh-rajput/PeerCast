from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import webauthn

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('core.urls')),
    path('webauthn/register/options', webauthn.register_options, name='webauthn_register_options'),
    path('webauthn/register/verify', webauthn.register_verify, name='webauthn_register_verify'),
    path('webauthn/authenticate/options', webauthn.authenticate_options, name='webauthn_authenticate_options'),
    path('webauthn/authenticate/verify', webauthn.authenticate_verify, name='webauthn_authenticate_verify'),
    
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)