import os
import django
from django.conf import settings
from django.template.loader import render_to_string
from django.urls import path

# Dummy view for URL resolution
def dummy_view(request):
    pass

urlpatterns = [
    path('logout/', dummy_view, name='logout'),
    path('login/', dummy_view, name='login'),
    path('register/', dummy_view, name='register'),
    path('invoke_step_function/', dummy_view, name='invoke_step_function'),
    path('get_presigned_url/', dummy_view, name='get_presigned_url'),
    path('invoke_endlist/', dummy_view, name='invoke_endlist'),
    path('invoke_end_list/', dummy_view, name='invoke_end_list'),
]

# Configure Django settings
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='secret',
        ROOT_URLCONF=__name__,
        TEMPLATES=[{
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [os.path.abspath('templates')],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        }],
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'core',
        ],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
        MIDDLEWARE=[
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
        ],
    )
    django.setup()

try:
    # Attempt to render the template
    from core.forms import RoomForm
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.test import RequestFactory
    
    request = RequestFactory().get('/rooms/create/')
    request.session = 'session'
    request._messages = FallbackStorage(request)
    request.user = type('User', (object,), {'is_authenticated': True})
    
    form = RoomForm()
    context = {'form': form, 'request': request}
    rendered = render_to_string('app/create_room.html', context, request=request)
    print("Template rendered successfully!")
except Exception as e:
    print(f"Template rendering failed: {e}")
    import traceback
    traceback.print_exc()
