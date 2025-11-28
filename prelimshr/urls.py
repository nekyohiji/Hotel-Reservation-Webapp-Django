from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('create-account/', views.create_account, name='create_account'),
    path('login/', views.login_view, name='login_view'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('reservations/', views.reservations, name='reservations'),
    path('', include('JSXHotel.urls')),
]
