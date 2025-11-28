from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from JSXHotel.models import Admin, HrAccount, Account

class MultiRoleBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Check Admin table
        try:
            admin_user = Admin.objects.get(username=username)
            if check_password(password, admin_user.password):
                return admin_user  # Return Admin user object
        except Admin.DoesNotExist:
            pass

        # Check HrAccount table
        try:
            hr_user = HrAccount.objects.get(username=username)
            if check_password(password, hr_user.password):
                return hr_user  # Return HR user object
        except HrAccount.DoesNotExist:
            pass

        # Check Account table (Guests)
        try:
            guest_user = Account.objects.get(username=username)
            if check_password(password, guest_user.password):
                return guest_user  # Return Guest user object
        except Account.DoesNotExist:
            pass

        return None  # Authentication failed

    def get_user(self, user_id):
        # Check all tables for the user ID
        try:
            return Admin.objects.get(pk=user_id)
        except Admin.DoesNotExist:
            pass

        try:
            return HrAccount.objects.get(pk=user_id)
        except HrAccount.DoesNotExist:
            pass

        try:
            return Account.objects.get(pk=user_id)
        except Account.DoesNotExist:
            pass

        return None
