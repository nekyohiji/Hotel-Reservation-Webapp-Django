from django.shortcuts import redirect

def role_required(role):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            user_role = request.session.get('user_role')
            if user_role != role:
                return redirect('logreg')  # Redirect unauthorized users
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator