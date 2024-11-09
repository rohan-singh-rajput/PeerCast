from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from core.models import UserProfile
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Room, UserProfile
from django.contrib import messages
from django.utils import timezone
import uuid

def home_view(request):
    return render(request, "app/index.html")


# Register view
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return redirect("register")

        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
            return redirect("register")

        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, ", ".join(e.messages))
            return redirect("register")

        user = UserProfile.objects.create_user(
            username=username, email=email, password=password
        )
        user.save()

        messages.success(request, "User registered successfully")
        return redirect("login")
    return render(request, "app/register.html")


#  login
def login_view(request):
    # Log out the user if they're already logged in
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard")  # Redirect to dashboard after login
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, "app/login.html")


def logout_view(request):
    logout(request)
    return redirect("home")


@login_required
def dashboard_view(request):
    if not request.user.is_authenticated:
        return redirect("login")  # Redirect to login if not authenticated
    current_hour = timezone.now().hour
    if current_hour < 12:
        greeting_time = 'morning'
    elif current_hour < 18:
        greeting_time = 'afternoon'
    else:
        greeting_time = 'evening'
    return render(request, 'app/dashboard.html', {'greeting_time': greeting_time})


# room creation
@login_required
def create_room_view(request):
    if request.method == "POST":
        room_name = request.POST.get("room_name")
        if not room_name:
            messages.error(request, "Room name is required.")
            return redirect("create_room")
        
        room = Room.objects.create(name=room_name, host=request.user)
        room.save()
        return redirect("join_room", room_id=room.id)
    
    return render(request, "app/create_room.html")


# View to join a room
@login_required
def join_room_view(request):
    return render(request, "app/join_room.html" )
