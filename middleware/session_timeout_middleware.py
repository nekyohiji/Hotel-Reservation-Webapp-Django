from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            last_activity = request.session.get('last_activity')
            now = datetime.now()

            if last_activity:
                last_activity_time = datetime.fromisoformat(last_activity)
                if now - last_activity_time > timedelta(seconds=settings.SESSION_COOKIE_AGE):
                    logout(request)
                    return redirect('logreg')  # Redirect to login page

            # Update last activity timestamp
            request.session['last_activity'] = now.isoformat()

        response = self.get_response(request)
        return response
