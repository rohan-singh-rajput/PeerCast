from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from django.contrib import messages
from django.utils import timezone, text
from django.conf import settings
from django.urls import reverse
from django.contrib import messages
from django.shortcuts import render, redirect
from .forms import RoomForm
from .models import Room
from botocore.exceptions import ClientError

import uuid
import os
import json
import boto3

from core.models import UserProfile, Room
from .forms import RoomForm
from .tasks import update_room_with_hls_url
from dotenv import read_dotenv

# Load environment variables
read_dotenv('.env')
config = os.environ


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
        return redirect("dashboard")

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
    """
    Displays a dashboard with a greeting based on the time of day
    and a list of available rooms.
    """
    # Greeting based on time of day
    current_hour = timezone.now().hour
    if current_hour < 12:
        greeting_time = "morning"
    elif current_hour < 18:
        greeting_time = "afternoon"
    else:
        greeting_time = "evening"

    # Fetch all rooms to display
    rooms = Room.objects.all()

    # Pass the rooms and greeting time to the template
    return render(request, "app/dashboard.html", {
        "greeting_time": greeting_time,
        "rooms": rooms
    })


import logging
logger = logging.getLogger(__name__)

def demo_room(request):
    return render(request,'app/room.html')

@login_required
def close_room(request, slug):
    """
    View to close a room. Only the host of the room can close it.
    """
    room = get_object_or_404(Room, slug=slug)

    # Ensure that only the host can close the room
    if request.user != room.host:
        messages.error(request, "Only the host can close the room.")
        return redirect('join_room', slug=room.slug)

    # Delete the room and its participants
    room.delete()
    messages.success(request, "The room has been successfully closed.")
    
    # Redirect to dashboard or home after closing the room
    return redirect('dashboard')


# join room 
@login_required
def join_room_view(request, slug):
    room = get_object_or_404(Room, slug=slug)
    
    # Add user as participant if not already added
    if request.user not in room.participants.all():
        room.participants.add(request.user)
        room.save()
    
    context = {
        'room': room,
    }
    return render(request, 'app/join_room.html', context)


def join_room_via_link(request):
    """
    Handles joining a room using a link or slug provided by the user.
    """
    room_slug = request.GET.get('room_slug', '').strip()
    
    if not room_slug:
        return HttpResponseBadRequest("Room link or slug is required.")

    room = get_object_or_404(Room, slug=room_slug)
    return redirect('join_room', slug=room.slug)


@login_required
def room_detail_view(request, slug):
    room = get_object_or_404(Room, slug=slug)
    participants = room.participants.all()

    # Add user to participants if not already present
    if request.user not in participants:
        room.participants.add(request.user)

    # Add `is_owner` to context
    is_owner = request.user == room.owner

    return render(request, 'app/join_room.html', {
        'room': room,
        'participants': participants,
        'is_owner': is_owner,  # Pass owner check to the template
    })


# Room list view
def room_list_view(request):
    rooms = Room.objects.all()
    return render(request, "app/room_list.html", {"rooms": rooms})


def room_view(request):
    return render(request, "app/room.html")


@csrf_protect
def create_room_view(request):
    if request.method == 'POST':
        form = RoomForm(request.POST)
        if form.is_valid():
            room = form.save(commit=False)
            room.host = request.user
            room.video_url = request.POST.get('video_url')
            room.save()
            return redirect('room_detail', slug=room.slug)
        else:
            messages.error(request, "Error creating room.")
    else:
        form = RoomForm()

    return render(request, 'app/create_room.html', {'form': form})


s3_client = boto3.client(
    's3',
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],
    aws_secret_access_key=os.environ['SECRET_KEY_AWS'],
    region_name=os.environ['REGION_AWS']
)

# Initialize Step Functions client
step_client = boto3.client(
    'stepfunctions',
    region_name=os.environ['REGION_AWS'],
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
    aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.environ['REGION_AWS'],
    aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
    aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles)
)

metadata_db = dynamodb.Table('metadata_db')


def upload_view(request):
    return render(request, 'upload_file.html')

@csrf_protect
def get_presigned_url(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        filename = data.get('filename')
        videoName = filename[:-4]
        extension = 'ts'

        chunk_number = data.get('chunkNumber')

        #Generate the chunk filename with chunk number
        chunk_filename = f"{videoName}_{chunk_number:04d}.{extension}"

        # Generate a presigned URL for this chunk
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': os.environ['BUCKET_NAME'],
                'Key': f"{videoName}/{chunk_filename}",
                'ContentType': 'video/mp2t'
            },
            ExpiresIn=180
        )

        return JsonResponse({'presigned_url': presigned_url})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_protect  # Use appropriate authentication in production
def start_step_function(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    
    try:
        # Parse JSON body
        data = json.loads(request.body)
        filename = data.get('filename')
        video_name = filename[:-4]
        output_bucket_name = 'output-hls-bucket'
        
        if not video_name:
            return JsonResponse({'error': 'Missing video_name.'}, status=400)
        
        # Prepare input for Step Functions
        input_payload = {
            'video_name': video_name,
            'output_bucket_name': output_bucket_name
        }
        
        # Start Step Function execution
        response = step_client.start_execution(
            stateMachineArn=os.environ['STATE_MACHINE_ARN'],
            input=json.dumps(input_payload),
            name=f"{video_name}_execution_{uuid.uuid4()}"  # Optional: Provide a unique name
        )

        print("State machine created.")
        
        return JsonResponse({
            'message': 'Step Function execution started successfully.',
            'executionArn': response.get('executionArn'),
            'startDate': response.get('startDate').isoformat()
        }, status=200)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    except step_client.exceptions.ExecutionAlreadyExists:
        return JsonResponse({'error': 'An execution with the same name already exists.'}, status=409)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

@csrf_protect
def update_endlist_db(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    try:
        data = json.loads(request.body)
        filename = data.get('filename')
        chunk_no = data.get('chunkIndex')
        video_name = filename[:-4]
        response = metadata_db.put_item(
            Item={
                'video_name': video_name,
                'chunkno_reso': str(chunk_no) + '9',
                'url': 'ENDLIST',
                'is_added': False
            }
        )
        print("Insert successful:", response)

        return JsonResponse({'message': 'Insert successful.'}, status=200)
            
    except ClientError as e:
        # Log the error message
        print("Failed to insert item:", e.response['Error']['Message'])
        
        # Return an error response
        return JsonResponse({'error': 'Failed to insert item into the database.'}, status=500)
    
    except json.JSONDecodeError:
        # Handle invalid JSON
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    
    except Exception as e:
        # Catch-all for any other exceptions
        print("An unexpected error occurred:", str(e))
        return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)