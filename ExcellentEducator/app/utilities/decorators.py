from django.shortcuts import redirect
from app.utilities.funcs import is_premium
from app.utilities.db import get_db
from django.contrib import messages
import time
from functools import wraps

db = get_db()

def authenticated_only(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get("user")  # Use .get() to avoid KeyError
        
        if not user:  # If user is None or missing
            return redirect('login')

        user_id = str(user.get("id"))  # Get user ID safely

        return view_func(request, *args, **kwargs)

    return wrapper

def logout_only(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if "user" in request.session:
            return redirect('home')
        return view_func(request, *args, **kwargs)
    return wrapper

def admin_only(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if "user" not in request.session or request.session["user"]["rank"] != 1:
            return redirect('teachers_only')
        return view_func(request, *args, **kwargs)
    return wrapper