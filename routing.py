from django.urls import path
from JSXHotel.consumers import ReservationConsumer

websocket_urlpatterns = [
    path('rsv_rq_ad/', ReservationConsumer.as_asgi()),
]
