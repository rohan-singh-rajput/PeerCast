# myapp/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.forms import AuthenticationForm
import uuid


def home_view(request):
    return render(request, "index.html")


def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return redirect("register")

        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, ", ".join(e.messages))
            return redirect("register")

        user = User.objects.create_user(username=username, password=password)
        user.save()

        messages.success(request, "User registered successfully")
        return redirect("login")

    return render(request, "register.html")


def login_view(request):
    # Log out the user if they're already logged in
    if request.user.is_authenticated:
        logout(request)

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("dashboard")  # Redirect to dashboard after login
            else:
                form.add_error(None, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, "login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("home") 


def dashboard_view(request):
    if not request.user.is_authenticated:
        return redirect("login")  # Redirect to login if not authenticated
    return render(request, "dashboard.html")


def create_meeting(request):
    if request.method == 'POST':
        # Process the form data
        uploaded_file = request.FILES.get('video_file')
        # (You would save the file and meeting details in your database here)
        
        # Generate a unique meeting link
        meeting_id = uuid.uuid4()
        meeting_link = request.build_absolute_uri(f'/meeting/{meeting_id}/')
        
        # Redirect or display meeting details with the link
        return render(request, 'meeting_created.html', {'meeting_link': meeting_link})
    
    return render(request, 'create_meeting.html')
