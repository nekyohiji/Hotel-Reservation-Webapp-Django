import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack  
import JSXHotel.routing as routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'prelimshr.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            routing.websocket_urlpatterns  # Reference the list directly from your routing.py
        )
    ),
})
