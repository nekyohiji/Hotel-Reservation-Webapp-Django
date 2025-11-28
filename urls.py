from django.urls import include, path
from django.conf.urls.static import static
from . import views
from django.conf import settings
import os

urlpatterns = [
    path('', views.index, name='login'), 
    path('logreg/', views.logreg, name='logreg'),
    path('dashboard/', views.dashboard, name='dashboard'), 
    #path('booking/', views.booking, name='booking'),
    path('reservations/', views.reservations, name='reservations'),
    path('account', views.account, name='account'), 
    #path('receptionist', views.receptionist, name='receptionist'), 
    path('walkins', views.walkin_reservation_view, name='walkins'),
    #path('home_ad', views.home_ad, name='home_ad'),
    #path('booking_ad', views.booking_ad, name='booking_ad'),
    #path('rsv_req_ad', views.rsv_req_ad, name='rsv_req_ad'),
    path('cncl_req_ad', views.cncl_req_ad, name='cncl_req_ad'),
    path('settlements_ad', views.settlements_list, name='settlements_ad'),
    path('acc_ad', views.acc_ad, name='acc_ad'),
    #path('blocklisted', views.blocklisted, name = 'blocklisted'),

    path('create-account/', views.create_account, name='create_account'),
    path('login-view/', views.login_view, name='login_view'),
    path('create-reservation/', views.create_reservation, name='create_reservation'),
    path('submit-walk-in-reservation/', views.submit_walk_in_reservation, name='submit_walk_in_reservation'),
    path('admin/homepage-edit/', views.admin_homepage_edit, name='admin_homepage_edit'),
    path('rsv_req_ad/', views.admin_reservations, name='admin_reservations'),
    path('update-request-status/<int:reservation_id>/', views.update_request_status, name='update_request_status'),
    path('manage-hr-accounts/', views.manage_hr_accounts, name='manage_hr_accounts'),
    path('update_hr_status/<str:username>/', views.update_hr_status, name='update_hr_status'),
    path('check-username/', views.check_username, name='check_username'),
    path('room-promotions/', views.room_promotions_view, name='room_promotions_view'),
    path('booking/', views.booking_view, name='booking'),
    path('booking_ad/', views.booking_ad_view, name='booking_ad_view'),
    path('deactivate_promotion/<str:room_id>/', views.deactivate_promotion, name='deactivate_promotion'),
    path('cancel-reservation/<int:reservation_id>/', views.cancel_reservation, name='cancel_reservation'),
    path('update-cancellation-status/<int:reservation_id>/', views.update_cancellation_status, name='update_cancellation_status'),
    path('home_ad/', views.admin_homepage_view, name='home_ad'),
    path('archived_bookings', views.archive_view, name = 'archived_bookings'),
    path('receptionist/', views.receptionist_view, name='receptionist'),
    path('update_status/', views.update_status, name='update_status'),
    path('reservations/update_settlement/<int:reference_id>/', views.update_settlement, name='update_settlement'),
    path('logout/', views.logout_view, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('hr_pass/', views.hr_pass_view, name='hr_pass'),


] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

