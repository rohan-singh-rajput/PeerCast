from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from core.models import UserProfile
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.forms import AuthenticationForm
import uuid
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm


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
    return render(request, "app/dashboard.html")
