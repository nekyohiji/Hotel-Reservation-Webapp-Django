from django.utils.deprecation import MiddlewareMixin
from JSXHotel.models import Account, Admin, HrAccount

class AnonymousUser:
    """Fallback user for unauthenticated requests."""
    is_authenticated = False

class CustomAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Retrieve user_id and user_role from the session
        user_id = request.session.get('user_id')
        user_role = request.session.get('user_role')

        if user_id and user_role:
            try:
                # Fetch the user based on their role
                if user_role == 'Admin':
                    request.user = Admin.objects.get(id=user_id)
                elif user_role == 'HR':
                    request.user = HrAccount.objects.get(id=user_id)
                elif user_role == 'Guest':
                    request.user = Account.objects.get(id=user_id)
                else:
                    request.user = AnonymousUser()  # Invalid role, fallback
            except (Admin.DoesNotExist, HrAccount.DoesNotExist, Account.DoesNotExist):
                request.user = AnonymousUser()  # User not found, fallback
        else:
            # No user_id or user_role in session, set to AnonymousUser
            request.user = AnonymousUser()
