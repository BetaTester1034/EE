# myapp/middleware.py

from django.http import HttpResponse
from django.shortcuts import render
from app.utilities.funcs import is_ip_blocked
from app.utilities.algorithms import bot_detection_algorithm

from app.config import IP_API_KEY
import requests

class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the user's IP address
        user_ip = request.META.get('REMOTE_ADDR')

        # Check if the user's IP is blocked using the is_ip_blocked function
        if is_ip_blocked(user_ip):
            if str(request.path).strip() != "/admin/dashboard/":
                return render(request, 'ip_blocked.html', status=403)

        # Proceed to the next middleware or view
        response = self.get_response(request)

        # Optionally modify the response before sending it back
        return response

class VPNBlocker:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user_ip = request.META.get('REMOTE_ADDR')
        url = f"https://vpnapi.io/api/{user_ip}?key={IP_API_KEY}"
        r = requests.get(url)
        security_info = r.json().get('security')

        try:
            using_ip_hider = security_info.get('vpn') or security_info.get('proxy') or security_info.get('tor') or security_info.get('relay')
        except AttributeError:
            using_ip_hider = False

        if security_info:
            if using_ip_hider:
                return render(request, 'vpn_detected.html', status=403)

        response = self.get_response(request)
        return response
    

class BotDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if bot_detection_algorithm(request) >= 0.6:
            return render(request, 'bot_detected.html', status=403)

        response = self.get_response(request)
        return response