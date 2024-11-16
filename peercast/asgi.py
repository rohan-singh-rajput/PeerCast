import os
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
import core.routing  # Replace 'yourapp' with your Django app name

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'peercast.settings') 

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            core.routing.websocket_urlpatterns  #  WebSocket routing
        )
    ),
})
