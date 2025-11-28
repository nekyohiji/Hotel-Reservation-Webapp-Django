from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from JSXHotel.models import Admin, HrAccount, Account

class CustomAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        print(f"Attempting authentication for username: {username}")

        # Try Admin authentication
        try:
            admin_user = Admin.objects.get(username=username)
            if check_password(password, admin_user.password):
                print(f"Admin authenticated: {username}")
                return admin_user
        except Admin.DoesNotExist:
            pass

        # Try HR authentication
        try:
            hr_user = HrAccount.objects.get(username=username)
            if check_password(password, hr_user.password):
                print(f"HR authenticated: {username}")
                return hr_user
        except HrAccount.DoesNotExist:
            pass

        # Try Guest authentication
        try:
            guest_user = Account.objects.get(username=username)
            if check_password(password, guest_user.password):
                print(f"Guest authenticated: {username}")
                return guest_user
        except Account.DoesNotExist:
            pass

        print(f"Authentication failed for username: {username}")
        return None

    def get_user(self, user_id):
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
            return None
