# # # from django.shortcuts import render, redirect, get_object_or_404
# # # from django.contrib.auth import authenticate, login, logout
# # # from django.contrib.auth.decorators import login_required
# # # from django.contrib.auth.forms import AuthenticationForm
# # # from django.contrib.auth.password_validation import validate_password
# # # from django.core.exceptions import ValidationError
# # # from django.http import JsonResponse, HttpResponseBadRequest
# # # from django.views.decorators.csrf import csrf_protect
# # # from django.views.decorators.http import require_http_methods, require_POST
# # # from django.contrib import messages
# # # from django.utils import timezone, text
# # # from django.conf import settings
# # # from django.urls import reverse
# # # from django.contrib import messages
# # # from django.shortcuts import render, redirect
# # # from .forms import RoomForm
# # # from .models import Room
# # # from botocore.exceptions import ClientError

# # # import uuid
# # # import os
# # # import json
# # # import boto3

# # # from core.models import UserProfile, Room
# # # from .forms import RoomForm
# # # from .tasks import update_room_with_hls_url
# # # from dotenv import read_dotenv

# # # # Load environment variables
# # # read_dotenv('.env')
# # # config = os.environ


# # # def home_view(request):
# # #     return render(request, "app/index.html")


# # # # Register view
# # # def register_view(request):
# # #     if request.method == "POST":
# # #         username = request.POST.get("username")
# # #         email = request.POST.get("email")
# # #         password = request.POST.get("password")

# # #         if UserProfile.objects.filter(username=username).exists():
# # #             messages.error(request, "Username already taken")
# # #             return redirect("register")

# # #         if UserProfile.objects.filter(email=email).exists():
# # #             messages.error(request, "Email already registered")
# # #             return redirect("register")

# # #         try:
# # #             validate_password(password)
# # #         except ValidationError as e:
# # #             messages.error(request, ", ".join(e.messages))
# # #             return redirect("register")

# # #         user = UserProfile.objects.create_user(
# # #             username=username, email=email, password=password
# # #         )
# # #         user.save()

# # #         messages.success(request, "User registered successfully")
# # #         return redirect("login")
# # #     return render(request, "app/register.html")


# # # #  login
# # # def login_view(request):
# # #     # Log out the user if they're already logged in
# # #     if request.user.is_authenticated:
# # #         return redirect("dashboard")

# # #     if request.method == "POST":
# # #         email = request.POST.get("email")
# # #         password = request.POST.get("password")
# # #         user = authenticate(request, email=email, password=password)

# # #         if user is not None:
# # #             login(request, user)
# # #             return redirect("dashboard")  # Redirect to dashboard after login
# # #         else:
# # #             messages.error(request, "Invalid email or password.")

# # #     return render(request, "app/login.html")


# # # def logout_view(request):
# # #     logout(request)
# # #     return redirect("home")

# # # @login_required
# # # def dashboard_view(request):
# # #     """
# # #     Displays a dashboard with a greeting based on the time of day
# # #     and a list of available rooms.
# # #     """
# # #     # Greeting based on time of day
# # #     current_hour = timezone.now().hour
# # #     if current_hour < 12:
# # #         greeting_time = "morning"
# # #     elif current_hour < 18:
# # #         greeting_time = "afternoon"
# # #     else:
# # #         greeting_time = "evening"

# # #     # Fetch all rooms to display
# # #     rooms = Room.objects.all()

# # #     # Pass the rooms and greeting time to the template
# # #     return render(request, "app/dashboard.html", {
# # #         "greeting_time": greeting_time,
# # #         "rooms": rooms
# # #     })


# # # import logging
# # # logger = logging.getLogger(__name__)

# # # def demo_room(request):
# # #     return render(request,'app/room.html')

# # # @login_required
# # # def close_room(request, slug):
# # #     """
# # #     View to close a room. Only the host of the room can close it.
# # #     """
# # #     room = get_object_or_404(Room, slug=slug)

# # #     # Ensure that only the host can close the room
# # #     if request.user != room.host:
# # #         messages.error(request, "Only the host can close the room.")
# # #         return redirect('join_room', slug=room.slug)

# # #     # Delete the room and its participants
# # #     room.delete()
# # #     messages.success(request, "The room has been successfully closed.")
    
# # #     # Redirect to dashboard or home after closing the room
# # #     return redirect('dashboard')


# # # # join room 
# # # @login_required
# # # def join_room_view(request, slug):
# # #     room = get_object_or_404(Room, slug=slug)
    
# # #     # Add user as participant if not already added
# # #     if request.user not in room.participants.all():
# # #         room.participants.add(request.user)
# # #         room.save()
    
# # #     context = {
# # #         'room': room,
# # #     }
# # #     return render(request, 'app/join_room.html', context)


# # # def join_room_via_link(request):
# # #     """
# # #     Handles joining a room using a link or slug provided by the user.
# # #     """
# # #     room_slug = request.GET.get('room_slug', '').strip()
    
# # #     if not room_slug:
# # #         return HttpResponseBadRequest("Room link or slug is required.")

# # #     room = get_object_or_404(Room, slug=room_slug)
# # #     return redirect('join_room', slug=room.slug)


# # # @login_required
# # # def room_detail_view(request, slug):
# # #     room = get_object_or_404(Room, slug=slug)
# # #     participants = room.participants.all()

# # #     # Add user to participants if not already present
# # #     if request.user not in participants:
# # #         room.participants.add(request.user)

# # #     # Add `is_owner` to context
# # #     is_owner = request.user == room.owner

# # #     return render(request, 'app/join_room.html', {
# # #         'room': room,
# # #         'participants': participants,
# # #         'is_owner': is_owner,  # Pass owner check to the template
# # #     })


# # # # Room list view
# # # def room_list_view(request):
# # #     rooms = Room.objects.all()
# # #     return render(request, "app/room_list.html", {"rooms": rooms})


# # # def room_view(request):
# # #     return render(request, "app/room.html")


# # # @csrf_protect
# # # def create_room_view(request):
# # #     if request.method == 'POST':
# # #         form = RoomForm(request.POST)
# # #         if form.is_valid():
# # #             room = form.save(commit=False)
# # #             room.host = request.user
# # #             room.video_url = request.POST.get('video_url')
# # #             room.save()
# # #             return redirect('room_detail', slug=room.slug)
# # #         else:
# # #             messages.error(request, "Error creating room.")
# # #     else:
# # #         form = RoomForm()

# # #     return render(request, 'app/create_room.html', {'form': form})


# # # s3_client = boto3.client(
# # #     's3',
# # #     aws_access_key_id=os.environ['ACCESS_KEY_AWS'],
# # #     aws_secret_access_key=os.environ['SECRET_KEY_AWS'],
# # #     region_name=os.environ['REGION_AWS']
# # # )

# # # # Initialize Step Functions client
# # # step_client = boto3.client(
# # #     'stepfunctions',
# # #     region_name=os.environ['REGION_AWS'],
# # #     aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
# # #     aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles
# # # )

# # # dynamodb = boto3.resource(
# # #     'dynamodb',
# # #     region_name=os.environ['REGION_AWS'],
# # #     aws_access_key_id=os.environ['ACCESS_KEY_AWS'],  # Optional if using IAM roles
# # #     aws_secret_access_key=os.environ['SECRET_KEY_AWS']  # Optional if using IAM roles)
# # # )

# # # metadata_db = dynamodb.Table('metadata_db')


# # # def upload_view(request):
# # #     return render(request, 'upload_file.html')

# # # @csrf_protect
# # # def get_presigned_url(request):
# # #     if request.method == 'POST':
# # #         data = json.loads(request.body)

# # #         filename = data.get('filename')
# # #         videoName = filename[:-4]
# # #         extension = 'ts'

# # #         chunk_number = data.get('chunkNumber')

# # #         #Generate the chunk filename with chunk number
# # #         chunk_filename = f"{videoName}_{chunk_number:04d}.{extension}"

# # #         # Generate a presigned URL for this chunk
# # #         presigned_url = s3_client.generate_presigned_url(
# # #             'put_object',
# # #             Params={
# # #                 'Bucket': os.environ['BUCKET_NAME'],
# # #                 'Key': f"{videoName}/{chunk_filename}",
# # #                 'ContentType': 'video/mp2t'
# # #             },
# # #             ExpiresIn=180
# # #         )

# # #         return JsonResponse({'presigned_url': presigned_url})
    
# # #     return JsonResponse({'error': 'Invalid request method'}, status=400)


# # # @csrf_protect  # Use appropriate authentication in production
# # # def start_step_function(request):
# # #     if request.method != 'POST':
# # #         return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    
# # #     try:
# # #         # Parse JSON body
# # #         data = json.loads(request.body)
# # #         filename = data.get('filename')
# # #         video_name = filename[:-4]
# # #         output_bucket_name = 'output-hls-bucket'
        
# # #         if not video_name:
# # #             return JsonResponse({'error': 'Missing video_name.'}, status=400)
        
# # #         # Prepare input for Step Functions
# # #         input_payload = {
# # #             'video_name': video_name,
# # #             'output_bucket_name': output_bucket_name
# # #         }
        
# # #         # Start Step Function execution
# # #         response = step_client.start_execution(
# # #             stateMachineArn=os.environ['STATE_MACHINE_ARN'],
# # #             input=json.dumps(input_payload),
# # #             name=f"{video_name}_execution_{uuid.uuid4()}"  # Optional: Provide a unique name
# # #         )

# # #         print("State machine created.")
        
# # #         return JsonResponse({
# # #             'message': 'Step Function execution started successfully.',
# # #             'executionArn': response.get('executionArn'),
# # #             'startDate': response.get('startDate').isoformat()
# # #         }, status=200)
    
# # #     except json.JSONDecodeError:
# # #         return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
# # #     except step_client.exceptions.ExecutionAlreadyExists:
# # #         return JsonResponse({'error': 'An execution with the same name already exists.'}, status=409)
# # #     except Exception as e:
# # #         return JsonResponse({'error': str(e)}, status=500)
    

# # # @csrf_protect
# # # def update_endlist_db(request):
# # #     if request.method != 'POST':
# # #         return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
# # #     try:
# # #         data = json.loads(request.body)
# # #         filename = data.get('filename')
# # #         chunk_no = data.get('chunkIndex')
# # #         video_name = filename[:-4]
# # #         response = metadata_db.put_item(
# # #             Item={
# # #                 'video_name': video_name,
# # #                 'chunkno_reso': str(chunk_no) + '9',
# # #                 'url': 'ENDLIST',
# # #                 'is_added': False
# # #             }
# # #         )
# # #         print("Insert successful:", response)

# # #         return JsonResponse({'message': 'Insert successful.'}, status=200)
            
# # #     except ClientError as e:
# # #         # Log the error message
# # #         print("Failed to insert item:", e.response['Error']['Message'])
        
# # #         # Return an error response
# # #         return JsonResponse({'error': 'Failed to insert item into the database.'}, status=500)
    
# # #     except json.JSONDecodeError:
# # #         # Handle invalid JSON
# # #         return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    
# # #     except Exception as e:
# # #         # Catch-all for any other exceptions
# # #         print("An unexpected error occurred:", str(e))
# # #         return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)


# # # # at the top of core/views.py (imports)
# # # from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
# # # from django.views.decorators.http import require_POST
# # # from django.views.decorators.csrf import csrf_exempt  # we'll use csrf token for front-end fetch; adjust accordingly
# # # from fido2.server import Fido2Server
# # # from fido2 import cbor
# # # from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
# # # from fido2.utils import websafe_encode, websafe_decode
# # # from django.contrib.auth import login as django_login
# # # from django.shortcuts import get_object_or_404

# # # # RP information — adjust your domain / rp name
# # # RP_ID = "localhost"        # change to your site's domain (no scheme)
# # # RP_NAME = "PeerCast"

# # # rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
# # # fido_server = Fido2Server(rp)

# # # # helper to get user by email or username
# # # from .models import UserProfile, Credential

# # # # -------- Register start --------
# # # @require_POST
# # # def webauthn_register_start(request):
# # #     """
# # #     POST payload: { "username": "<username or email>", "name": "<display name>" }
# # #     Response: Attestation options (CBOR-safe JSON)
# # #     """
# # #     data = json.loads(request.body)
# # #     username = data.get("username")
# # #     display_name = data.get("name", username)

# # #     if not username:
# # #         return JsonResponse({"error": "username required"}, status=400)

# # #     # find or create user (we'll create user record without password)
# # #     user, created = UserProfile.objects.get_or_create(email=username, defaults={"username": username})
# # #     # create user entity
# # #     user_entity = PublicKeyCredentialUserEntity(str(user.id).encode("utf-8"), username, display_name)

# # #     # excludeCredentials: existing credentials for this user (to prevent duplicates)
# # #     existing = []
# # #     for cred in user.credentials.all():
# # #         existing.append({
# # #             "type": "public-key",
# # #             "id": cred.credential_id  # fido2 will accept raw bytes
# # #         })

# # #     options, state = fido_server.register_begin(user_entity, credentials=existing)

# # #     # Save state
# # #     request.session["webauthn_reg_state"] = state
# # #     request.session["webauthn_reg_user_id"] = user.id

# # #     # Convert CBOR / bytes → base64url JSON-safe
# # #     def to_json_safe(obj):
# # #         from fido2.utils import websafe_encode
# # #         if isinstance(obj, bytes):
# # #             return websafe_encode(obj).decode()
# # #         if isinstance(obj, list):
# # #             return [to_json_safe(x) for x in obj]
# # #         if isinstance(obj, dict):
# # #             return {k: to_json_safe(v) for k, v in obj.items()}
# # #         return obj

# # #     return JsonResponse(to_json_safe(options))

# # # # -------- Register complete --------
# # # @require_POST
# # # def webauthn_register_complete(request):
# # #     """
# # #     POST payload: attestation response from navigator.credentials.create() (JSON)
# # #     """
# # #     data = json.loads(request.body)
# # #     # get state from session
# # #     state = request.session.get('webauthn_reg_state')
# # #     user_id = request.session.get('webauthn_reg_user_id')
# # #     if not state or not user_id:
# # #         return JsonResponse({"error": "No registration in progress"}, status=400)

# # #     user = UserProfile.objects.get(id=user_id)

# # #     attestation_result = fido_server.register_complete(state, data)
# # #     # attestation_result.credential_data contains credential public key and id and sign_count

# # #     cred_data = attestation_result.credential_data
# # #     cred_id = cred_data.credential_id
# # #     pubkey = cred_data.public_key
# # #     sign_count = cred_data.sign_count
# # #     transports = data.get('transports', None)

# # #     # Persist new credential
# # #     cred = Credential.objects.create(
# # #         user=user,
# # #         credential_id=cred_id,
# # #         public_key=pubkey,
# # #         sign_count=sign_count,
# # #         transports=transports or [],
# # #         name=f"Device {Credential.objects.filter(user=user).count()+1}"
# # #     )

# # #     # optional: log the user in
# # #     django_login(request, user)

# # #     # cleanup session
# # #     request.session.pop('webauthn_reg_state', None)
# # #     request.session.pop('webauthn_reg_user_id', None)

# # #     return JsonResponse({"status": "ok"})

# # # # -------- Login start (assertion options) --------
# # # @require_POST
# # # def webauthn_login_start(request):
# # #     """
# # #     POST payload: { "username": "<email or username>" }
# # #     Response: assertion options (challenge + allowedCredentials)
# # #     """
# # #     data = json.loads(request.body)
# # #     username = data.get("username")
# # #     if not username:
# # #         return JsonResponse({"error": "username required"}, status=400)
# # #     try:
# # #         user = UserProfile.objects.get(email=username)
# # #     except UserProfile.DoesNotExist:
# # #         return JsonResponse({"error": "user not found"}, status=404)

# # #     # allowed credentials: all credentials for this user
# # #     credentials = []
# # #     for cred in user.credentials.all():
# # #         credentials.append({"type": "public-key", "id": cred.credential_id})

# # #     auth_data, state = fido_server.authenticate_begin(credentials)
# # #     # save state and user id in session
# # #     request.session['webauthn_auth_state'] = state
# # #     request.session['webauthn_auth_user_id'] = user.id

# # #     return JsonResponse(auth_data)

# # # # -------- Login complete (assertion verification) --------
# # # @require_POST
# # # def webauthn_login_complete(request):
# # #     """
# # #     POST payload: assertion response from navigator.credentials.get()
# # #     """
# # #     data = json.loads(request.body)
# # #     state = request.session.get('webauthn_auth_state')
# # #     user_id = request.session.get('webauthn_auth_user_id')
# # #     if not state or not user_id:
# # #         return JsonResponse({"error": "No auth in progress"}, status=400)

# # #     user = UserProfile.objects.get(id=user_id)

# # #     # find the matching credential in DB by id (clientData will contain raw id)
# # #     credential_id_b64 = data.get("id")  # client sends id as base64url in many libs; ensure shape
# # #     # fido2 expects the data directly as provided by front-end (binary), so pass the whole client response
# # #     auth_result = fido_server.authenticate_complete(state, user.credentials.values_list('public_key', flat=True), data)
# # #     # authenticate_complete will return credential_data and sign_count etc.

# # #     # But to update sign count we need the credential object
# # #     # Find by credential id (binary)
# # #     from base64 import urlsafe_b64decode, b64decode
# # #     raw_id = websafe_decode(data.get("rawId")) if data.get("rawId") else None
# # #     # Attempt to find credential record
# # #     cred = None
# # #     if raw_id:
# # #         try:
# # #             cred = Credential.objects.get(credential_id=raw_id)
# # #         except Credential.DoesNotExist:
# # #             cred = None

# # #     # Update sign_count in DB if verification passed
# # #     if auth_result.signature_count is not None and cred:
# # #         cred.sign_count = auth_result.signature_count
# # #         cred.save()

# # #     # Log user in
# # #     django_login(request, user)

# # #     # cleanup
# # #     request.session.pop('webauthn_auth_state', None)
# # #     request.session.pop('webauthn_auth_user_id', None)

# # #     return JsonResponse({"status": "ok"})

# # # views.py (complete file)
# from django.shortcuts import render, redirect, get_object_or_404
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.password_validation import validate_password
# from django.core.exceptions import ValidationError
# from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
# from django.views.decorators.csrf import csrf_protect
# from django.views.decorators.http import require_http_methods, require_POST
# from django.contrib import messages
# from django.utils import timezone, text
# from django.conf import settings
# from django.urls import reverse
# import logging

# # Local imports
# from .forms import RoomForm
# from .models import Room, Credential  # ensure Credential model exists in your core/models.py
# from core.models import UserProfile
# from .tasks import update_room_with_hls_url

# # AWS / other libs
# import uuid
# import os
# import json
# import boto3
# from botocore.exceptions import ClientError
# from dotenv import read_dotenv

# # Load environment variables
# read_dotenv('.env')
# config = os.environ

# logger = logging.getLogger(__name__)

# # -----------------------
# # Basic site views
# # -----------------------
# def home_view(request):
#     return render(request, "app/index.html")


# # Register view (kept for backward compatibility - but you'll use WebAuthn)
# def register_view(request):
#     if request.method == "POST":
#         username = request.POST.get("username")
#         email = request.POST.get("email")
#         password = request.POST.get("password")

#         if UserProfile.objects.filter(username=username).exists():
#             messages.error(request, "Username already taken")
#             return redirect("register")

#         if UserProfile.objects.filter(email=email).exists():
#             messages.error(request, "Email already registered")
#             return redirect("register")

#         try:
#             validate_password(password)
#         except ValidationError as e:
#             messages.error(request, ", ".join(e.messages))
#             return redirect("register")

#         user = UserProfile.objects.create_user(
#             username=username, email=email, password=password
#         )
#         user.save()

#         messages.success(request, "User registered successfully")
#         return redirect("login")
#     return render(request, "app/register.html")


# # login (kept for backward compatibility - WebAuthn endpoints will be used)
# def login_view(request):
#     # Log out the user if they're already logged in
#     if request.user.is_authenticated:
#         return redirect("dashboard")

#     if request.method == "POST":
#         email = request.POST.get("email")
#         password = request.POST.get("password")
#         user = authenticate(request, email=email, password=password)

#         if user is not None:
#             login(request, user)
#             return redirect("dashboard")  # Redirect to dashboard after login
#         else:
#             messages.error(request, "Invalid email or password.")

#     return render(request, "app/login.html")


# def logout_view(request):
#     logout(request)
#     return redirect("home")


# @login_required
# def dashboard_view(request):
#     """
#     Displays a dashboard with a greeting based on the time of day
#     and a list of available rooms.
#     """
#     # Greeting based on time of day
#     current_hour = timezone.now().hour
#     if current_hour < 12:
#         greeting_time = "morning"
#     elif current_hour < 18:
#         greeting_time = "afternoon"
#     else:
#         greeting_time = "evening"

#     # Fetch all rooms to display
#     rooms = Room.objects.all()

#     # Pass the rooms and greeting time to the template
#     return render(request, "app/dashboard.html", {
#         "greeting_time": greeting_time,
#         "rooms": rooms
#     })


# def demo_room(request):
#     return render(request,'app/room.html')


# @login_required
# def close_room(request, slug):
#     """
#     View to close a room. Only the host of the room can close it.
#     """
#     room = get_object_or_404(Room, slug=slug)

#     # Ensure that only the host can close the room
#     if request.user != room.host:
#         messages.error(request, "Only the host can close the room.")
#         return redirect('join_room', slug=room.slug)

#     # Delete the room and its participants
#     room.delete()
#     messages.success(request, "The room has been successfully closed.")
    
#     # Redirect to dashboard or home after closing the room
#     return redirect('dashboard')


# # join room 
# @login_required
# def join_room_view(request, slug):
#     room = get_object_or_404(Room, slug=slug)
    
#     # Add user as participant if not already added
#     if request.user not in room.participants.all():
#         room.participants.add(request.user)
#         room.save()
    
#     context = {
#         'room': room,
#     }
#     return render(request, 'app/join_room.html', context)


# def join_room_via_link(request):
#     """
#     Handles joining a room using a link or slug provided by the user.
#     """
#     room_slug = request.GET.get('room_slug', '').strip()
    
#     if not room_slug:
#         return HttpResponseBadRequest("Room link or slug is required.")

#     room = get_object_or_404(Room, slug=room_slug)
#     return redirect('join_room', slug=room.slug)


# @login_required
# def room_detail_view(request, slug):
#     room = get_object_or_404(Room, slug=slug)
#     participants = room.participants.all()

#     # Add user to participants if not already present
#     if request.user not in participants:
#         room.participants.add(request.user)

#     # Add `is_owner` to context
#     is_owner = request.user == getattr(room, "owner", None) or request.user == getattr(room, "host", None)

#     return render(request, 'app/join_room.html', {
#         'room': room,
#         'participants': participants,
#         'is_owner': is_owner,  # Pass owner check to the template
#     })


# # Room list view
# def room_list_view(request):
#     rooms = Room.objects.all()
#     return render(request, "app/room_list.html", {"rooms": rooms})


# def room_view(request):
#     return render(request, "app/room.html")


# @csrf_protect
# def create_room_view(request):
#     if request.method == 'POST':
#         form = RoomForm(request.POST)
#         if form.is_valid():
#             room = form.save(commit=False)
#             room.host = request.user
#             room.video_url = request.POST.get('video_url')
#             room.save()
#             return redirect('room_detail', slug=room.slug)
#         else:
#             messages.error(request, "Error creating room.")
#     else:
#         form = RoomForm()

#     return render(request, 'app/create_room.html', {'form': form})


# # -----------------------
# # AWS / Step Function / DynamoDB clients (unchanged)
# # -----------------------
# s3_client = boto3.client(
#     's3',
#     aws_access_key_id=os.environ.get('ACCESS_KEY_AWS'),
#     aws_secret_access_key=os.environ.get('SECRET_KEY_AWS'),
#     region_name=os.environ.get('REGION_AWS')
# )

# # Initialize Step Functions client
# step_client = boto3.client(
#     'stepfunctions',
#     region_name=os.environ.get('REGION_AWS'),
#     aws_access_key_id=os.environ.get('ACCESS_KEY_AWS'),
#     aws_secret_access_key=os.environ.get('SECRET_KEY_AWS')
# )

# dynamodb = boto3.resource(
#     'dynamodb',
#     region_name=os.environ.get('REGION_AWS'),
#     aws_access_key_id=os.environ.get('ACCESS_KEY_AWS'),
#     aws_secret_access_key=os.environ.get('SECRET_KEY_AWS')
# )

# metadata_db = dynamodb.Table('metadata_db')


# def upload_view(request):
#     return render(request, 'upload_file.html')


# @csrf_protect
# def get_presigned_url(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)

#         filename = data.get('filename')
#         if not filename:
#             return JsonResponse({'error': 'filename required'}, status=400)

#         videoName = filename[:-4]
#         extension = 'ts'

#         chunk_number = data.get('chunkNumber')

#         #Generate the chunk filename with chunk number
#         chunk_filename = f"{videoName}_{chunk_number:04d}.{extension}"

#         # Generate a presigned URL for this chunk
#         presigned_url = s3_client.generate_presigned_url(
#             'put_object',
#             Params={
#                 'Bucket': os.environ.get('BUCKET_NAME'),
#                 'Key': f"{videoName}/{chunk_filename}",
#                 'ContentType': 'video/mp2t'
#             },
#             ExpiresIn=180
#         )

#         return JsonResponse({'presigned_url': presigned_url})
    
#     return JsonResponse({'error': 'Invalid request method'}, status=400)


# @csrf_protect  # Use appropriate authentication in production
# def start_step_function(request):
#     if request.method != 'POST':
#         return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
    
#     try:
#         # Parse JSON body
#         data = json.loads(request.body)
#         filename = data.get('filename')
#         if not filename:
#             return JsonResponse({'error': 'Missing filename.'}, status=400)

#         video_name = filename[:-4]
#         output_bucket_name = 'output-hls-bucket'
        
#         # Prepare input for Step Functions
#         input_payload = {
#             'video_name': video_name,
#             'output_bucket_name': output_bucket_name
#         }
        
#         # Start Step Function execution
#         response = step_client.start_execution(
#             stateMachineArn=os.environ.get('STATE_MACHINE_ARN'),
#             input=json.dumps(input_payload),
#             name=f"{video_name}_execution_{uuid.uuid4()}"  # Optional: Provide a unique name
#         )

#         logger.info("State machine created: %s", response.get('executionArn'))
        
#         return JsonResponse({
#             'message': 'Step Function execution started successfully.',
#             'executionArn': response.get('executionArn'),
#             'startDate': response.get('startDate').isoformat() if response.get('startDate') else None
#         }, status=200)
    
#     except json.JSONDecodeError:
#         return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
#     except step_client.exceptions.ExecutionAlreadyExists:
#         return JsonResponse({'error': 'An execution with the same name already exists.'}, status=409)
#     except Exception as e:
#         logger.exception("Failed to start step function")
#         return JsonResponse({'error': str(e)}, status=500)
    

# @csrf_protect
# def update_endlist_db(request):
#     if request.method != 'POST':
#         return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)
#     try:
#         data = json.loads(request.body)
#         filename = data.get('filename')
#         chunk_no = data.get('chunkIndex')
#         if not filename or chunk_no is None:
#             return JsonResponse({'error': 'filename and chunkIndex required'}, status=400)

#         video_name = filename[:-4]
#         response = metadata_db.put_item(
#             Item={
#                 'video_name': video_name,
#                 'chunkno_reso': str(chunk_no) + '9',
#                 'url': 'ENDLIST',
#                 'is_added': False
#             }
#         )
#         logger.info("Insert successful into DynamoDB: %s", response)

#         return JsonResponse({'message': 'Insert successful.'}, status=200)
            
#     except ClientError as e:
#         logger.exception("Failed to insert item into DynamoDB")
#         return JsonResponse({'error': 'Failed to insert item into the database.'}, status=500)
    
#     except json.JSONDecodeError:
#         # Handle invalid JSON
#         return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)
    
#     except Exception as e:
#         logger.exception("An unexpected error occurred in update_endlist_db")
#         return JsonResponse({'error': 'An unexpected error occurred.'}, status=500)


# # --------------------------------------------------------------------
# #   WEBAUTHN SECTION (FULLY UPDATED FOR fido2==2.0.0)
# # --------------------------------------------------------------------
# # Note: This section uses Django sessions to keep FIDO2 server state
# # and expects a Credential model with fields:
# #   - user (FK to UserProfile)
# #   - credential_id (BinaryField)
# #   - public_key (BinaryField)
# #   - sign_count (BigIntegerField)
# #   - name (CharField)
# #
# # Keep the front-end JS to convert base64url <-> ArrayBuffer
# # (templates/register.html and login.html should call these endpoints).
# # --------------------------------------------------------------------

# from fido2.server import Fido2Server
# from fido2.webauthn import (
#     PublicKeyCredentialRpEntity,
#     PublicKeyCredentialUserEntity
# )
# from fido2.utils import websafe_encode, websafe_decode

# from django.views.decorators.http import require_POST
# from django.contrib.auth import login as django_login

# # Correct RP values for local dev
# RP_ID = getattr(settings, "RP_ID", "localhost")  # MUST NOT include :8000
# RP_NAME = getattr(settings, "RP_NAME", "PeerCast")

# rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
# fido_server = Fido2Server(rp)

# # Use the Credential model you defined
# # from .models import Credential  # already imported at top of file

# # -----------------------
# # Helper: JSON Safe Encode
# # -----------------------
# def to_json_safe(obj):
#     """Recursively convert bytes → base64url strings for JSON."""
#     if isinstance(obj, (bytes, bytearray)):
#         return websafe_encode(obj).decode()
#     if isinstance(obj, dict):
#         return {k: to_json_safe(v) for k, v in obj.items()}
#     if isinstance(obj, list):
#         return [to_json_safe(v) for v in obj]
#     return obj


# # -----------------------
# # Helper: Decode Client Base64URL → bytes
# # -----------------------
# def from_client(obj):
#     """Convert expected base64url fields from client into bytes."""
#     if isinstance(obj, dict):
#         new = {}
#         for k, v in obj.items():
#             if k in (
#                 "rawId", "id",
#                 "clientDataJSON", "attestationObject",
#                 "authenticatorData", "signature",
#                 "userHandle"
#             ):
#                 new[k] = None if v is None else websafe_decode(v)
#             elif isinstance(v, (dict, list)):
#                 new[k] = from_client(v)
#             else:
#                 new[k] = v
#         return new

#     if isinstance(obj, list):
#         return [from_client(v) for v in obj]

#     return obj


# # --------------------------------------------------------------------
# #   REGISTER START (generate credential options)
# # --------------------------------------------------------------------
# @require_POST
# def webauthn_register_start(request):
#     """
#     Client sends:
#     { "username": "email", "name": "<optional>" }

#     We return JSON-safe publicKey options.
#     """
#     try:
#         body = json.loads(request.body)
#         print("Body: ", body)
#     except Exception:
#         return JsonResponse({"error": "invalid json"}, status=400)

#     username = body.get("username")
#     display_name = body.get("name", username)

#     if not username:
#         return JsonResponse({"error": "username required"}, status=400)

#     # Find or create user
#     user_obj, _ = UserProfile.objects.get_or_create(
#         email=body.get("username"),
#         defaults={"username": username}
#     )

#     # WebAuthn user entity (ID MUST be bytes)
#     user_entity = PublicKeyCredentialUserEntity(
#         id=str(user_obj.id).encode(),
#         name=username,
#         display_name=display_name
#     )

#     # Prevent duplicate credentials
#     existing_credentials = [
#         {"type": "public-key", "id": c.credential_id}
#         for c in user_obj.credentials.all()
#     ]

#     # Start WebAuthn create ceremony
#     options, state = fido_server.register_begin(
#         user=user_entity,
#         credentials=existing_credentials
#     )


#     print('Options!!: ', options.public_key)

#     request.session["webauthn_reg_state"] = state
#     request.session["webauthn_reg_user_id"] = user_obj.id

#     # Convert to JSON-safe structure
#     return JsonResponse(to_json_safe(options))


# # --------------------------------------------------------------------
# #   REGISTER COMPLETE (verify attestation)
# # --------------------------------------------------------------------
# @require_POST
# def webauthn_register_complete(request):
#     try:
#         body = json.loads(request.body)
#         print("Body: ", body)
#     except Exception:
#         return JsonResponse({"error": "invalid json"}, status=400)

#     state = request.session.get("webauthn_reg_state")
#     user_id = request.session.get("webauthn_reg_user_id")

#     if not state or not user_id:
#         return JsonResponse({"error": "no registration in progress"}, status=400)

#     user_obj = UserProfile.objects.get(id=user_id)

#     # Convert base64 -> bytes
#     client_data = from_client(body)

#     # Verify attestation
#     try:
#         result = fido_server.register_complete(
#             state,
#             client_data
#         )
#     except Exception as e:
#         logger.exception("WebAuthn register_complete failed")
#         return JsonResponse({"error": str(e)}, status=400)

#     cred_data = result.credential_data

#     # Save credential
#     Credential.objects.create(
#         user=user_obj,
#         credential_id=cred_data.credential_id,
#         public_key=cred_data.public_key,
#         sign_count=cred_data.sign_count,
#         transports=[],  # optional
#         name=f"Device {Credential.objects.filter(user=user_obj).count()+1}"
#     )

#     # Log in user
#     django_login(request, user_obj)

#     # Cleanup
#     request.session.pop("webauthn_reg_state", None)
#     request.session.pop("webauthn_reg_user_id", None)

#     return JsonResponse({"status": "ok"})


# # --------------------------------------------------------------------
# #   LOGIN START (generate assertion options)
# # --------------------------------------------------------------------
# @require_POST
# def webauthn_login_start(request):
#     try:
#         body = json.loads(request.body)
#     except Exception:
#         return JsonResponse({"error": "invalid json"}, status=400)

#     username = body.get("username")

#     if not username:
#         return JsonResponse({"error": "username required"}, status=400)

#     try:
#         user_obj = UserProfile.objects.get(email=username)
#     except UserProfile.DoesNotExist:
#         return JsonResponse({"error": "user not found"}, status=404)

#     allow_credentials = [
#         {"type": "public-key", "id": c.credential_id}
#         for c in user_obj.credentials.all()
#     ]

#     options, state = fido_server.authenticate_begin(allow_credentials)

#     request.session["webauthn_auth_state"] = state
#     request.session["webauthn_auth_user_id"] = user_obj.id

#     return JsonResponse(to_json_safe(options))


# # --------------------------------------------------------------------
# #   LOGIN COMPLETE (verify assertion)
# # --------------------------------------------------------------------
# @require_POST
# def webauthn_login_complete(request):
#     try:
#         body = json.loads(request.body)
#     except Exception:
#         return JsonResponse({"error": "invalid json"}, status=400)

#     state = request.session.get("webauthn_auth_state")
#     user_id = request.session.get("webauthn_auth_user_id")

#     if not state or not user_id:
#         return JsonResponse({"error": "no auth in progress"}, status=400)

#     user_obj = UserProfile.objects.get(id=user_id)

#     # Convert client assertion into bytes
#     client_data = from_client(body)

#     # Build stored creds list (required by fido2==2.0.0)
#     stored_creds = [
#         {
#             "credential_id": c.credential_id,
#             "public_key": c.public_key,
#             "sign_count": c.sign_count,
#         }
#         for c in user_obj.credentials.all()
#     ]

#     # Verify assertion
#     try:
#         result = fido_server.authenticate_complete(
#             state=state,
#             credentials=stored_creds,
#             response=client_data
#         )
#     except Exception as e:
#         logger.exception("WebAuthn authenticate_complete failed")
#         return JsonResponse({"error": str(e)}, status=400)

#     # Update counter
#     used_cred_id = result.credential_id
#     try:
#         cred_obj = user_obj.credentials.get(credential_id=used_cred_id)
#         cred_obj.sign_count = result.signature_count
#         cred_obj.save()
#     except Credential.DoesNotExist:
#         logger.warning("Credential used in assertion not found in DB")

#     # Log user in
#     django_login(request, user_obj)

#     # Cleanup
#     request.session.pop("webauthn_auth_state", None)
#     request.session.pop("webauthn_auth_user_id", None)

#     return JsonResponse({"status": "ok"})


# -------------------------------------------------------------
# views.py (COMPLETE FILE WITH FULLY UPDATED WEBAUTHN SUPPORT)
# -------------------------------------------------------------

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
from django.utils import timezone
from django.conf import settings

import logging
import uuid
import os
import json
import boto3

from botocore.exceptions import ClientError
from dotenv import read_dotenv

from .forms import RoomForm
from .models import Room, Credential
from core.models import UserProfile
from .tasks import update_room_with_hls_url


# Load environment variables
read_dotenv(".env")
config = os.environ

logger = logging.getLogger(__name__)


# ----------------------- HOME -----------------------
def home_view(request):
    return render(request, "app/index.html")


# ----------------------- AUTH (fallback password login) -----------------------
def register_view(request):
    """Legacy password registration — still kept, but WebAuthn replaces it."""
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
        messages.success(request, "User registered successfully")
        return redirect("login")

    return render(request, "app/register.html")


def login_view(request):
    """ Legacy login — kept only for fallback """
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, email=email, password=password)

        if user:
            login(request, user)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, "app/login.html")


def logout_view(request):
    logout(request)
    return redirect("home")


# ----------------------- DASHBOARD -----------------------
@login_required
def dashboard_view(request):
    current_hour = timezone.now().hour
    if current_hour < 12:
        greeting_time = "morning"
    elif current_hour < 18:
        greeting_time = "afternoon"
    else:
        greeting_time = "evening"

    rooms = Room.objects.all()

    return render(request, "app/dashboard.html", {
        "greeting_time": greeting_time,
        "rooms": rooms
    })


# ----------------------- ROOM VIEWS -----------------------
def demo_room(request):
    return render(request, "app/room.html")


@login_required
def close_room(request, slug):
    room = get_object_or_404(Room, slug=slug)

    if request.user != room.host:
        messages.error(request, "Only the host can close the room.")
        return redirect("join_room", slug=room.slug)

    room.delete()
    messages.success(request, "The room has been successfully closed.")
    return redirect("dashboard")


@login_required
def join_room_view(request, slug):
    room = get_object_or_404(Room, slug=slug)

    if request.user not in room.participants.all():
        room.participants.add(request.user)

    return render(request, "app/join_room.html", {"room": room})


def join_room_via_link(request):
    room_slug = request.GET.get("room_slug", "").strip()

    if not room_slug:
        return HttpResponseBadRequest("Room link or slug is required.")

    room = get_object_or_404(Room, slug=room_slug)
    return redirect("join_room", slug=room.slug)


@login_required
def room_detail_view(request, slug):
    room = get_object_or_404(Room, slug=slug)
    participants = room.participants.all()

    if request.user not in participants:
        room.participants.add(request.user)

    is_owner = request.user == getattr(room, "owner", None) or request.user == getattr(room, "host", None)

    return render(request, "app/join_room.html", {
        "room": room,
        "participants": participants,
        "is_owner": is_owner
    })


def room_list_view(request):
    return render(request, "app/room_list.html", {"rooms": Room.objects.all()})


def room_view(request):
    return render(request, "app/room.html")


@csrf_protect
def create_room_view(request):
    if request.method == "POST":
        form = RoomForm(request.POST)
        if form.is_valid():
            room = form.save(commit=False)
            room.host = request.user
            room.video_url = request.POST.get("video_url")
            room.save()
            return redirect("room_detail", slug=room.slug)
        messages.error(request, "Error creating room.")

    return render(request, "app/create_room.html", {"form": RoomForm()})


# ----------------------- AWS / HLS PROCESSING -----------------------
s3_client = boto3.client(
    "s3",
    aws_access_key_id=os.environ.get("ACCESS_KEY_AWS"),
    aws_secret_access_key=os.environ.get("SECRET_KEY_AWS"),
    region_name=os.environ.get("REGION_AWS")
)

step_client = boto3.client(
    "stepfunctions",
    region_name=os.environ.get("REGION_AWS"),
    aws_access_key_id=os.environ.get("ACCESS_KEY_AWS"),
    aws_secret_access_key=os.environ.get("SECRET_KEY_AWS")
)

dynamodb = boto3.resource(
    "dynamodb",
    region_name=os.environ.get("REGION_AWS"),
    aws_access_key_id=os.environ.get("ACCESS_KEY_AWS"),
    aws_secret_access_key=os.environ.get("SECRET_KEY_AWS")
)

metadata_db = dynamodb.Table("metadata_db")


def upload_view(request):
    return render(request, "upload_file.html")


@csrf_protect
def get_presigned_url(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request"}, status=400)

    data = json.loads(request.body)

    filename = data.get("filename")
    if not filename:
        return JsonResponse({"error": "filename required"}, status=400)

    chunk_number = data.get("chunkNumber")
    video_name = filename[:-4]
    chunk_filename = f"{video_name}_{chunk_number:04d}.ts"

    presigned_url = s3_client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": os.environ.get("BUCKET_NAME"),
            "Key": f"{video_name}/{chunk_filename}",
            "ContentType": "video/mp2t"
        },
        ExpiresIn=180
    )

    return JsonResponse({"presigned_url": presigned_url})


@csrf_protect
def start_step_function(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
        filename = data.get("filename")

        video_name = filename[:-4]
        output_bucket_name = "output-hls-bucket"

        response = step_client.start_execution(
            stateMachineArn=os.environ.get("STATE_MACHINE_ARN"),
            input=json.dumps({
                "video_name": video_name,
                "output_bucket_name": output_bucket_name
            }),
            name=f"{video_name}_exec_{uuid.uuid4()}"
        )

        return JsonResponse({
            "message": "Step Function started",
            "executionArn": response.get("executionArn")
        })
    except Exception as e:
        logger.exception("StepFunction error")
        return JsonResponse({"error": str(e)}, status=500)


@csrf_protect
def update_endlist_db(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
        filename = data.get("filename")
        chunk_no = data.get("chunkIndex")

        video_name = filename[:-4]

        metadata_db.put_item(Item={
            "video_name": video_name,
            "chunkno_reso": str(chunk_no) + "9",
            "url": "ENDLIST",
            "is_added": False
        })

        return JsonResponse({"message": "Insert successful"})
    except Exception as e:
        logger.exception("Endlist DB error")
        return JsonResponse({"error": str(e)}, status=500)


# -------------------------------------------------------------
#                  WEBAUTHN SECTION
# -------------------------------------------------------------
from fido2.server import (
    Fido2Server,
)
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from fido2.webauthn import PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode, websafe_decode
import base64


# Required for WebAuthn
RP_ID = "localhost"  
RP_NAME = "PeerCast"

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
fido_server = Fido2Server(rp)


def decode_client(data):
    """Convert base64url fields from client → bytes"""
    out = {}
    for k, v in data.items():
        if isinstance(v, dict):
            out[k] = decode_client(v)
        elif k in [
            "rawId",
            "id",
            "clientDataJSON",
            "attestationObject",
            "authenticatorData",
            "signature",
            "userHandle",
        ]:
            out[k] = websafe_decode(v) if v else None
        else:
            out[k] = v
    return out

# ---------- helpers ----------
def b64u(b: bytes) -> str:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b64u expects bytes")
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64u_to_bytes(s: str) -> bytes:
    if s is None:
        return b''
    if isinstance(s, str):
        s_bytes = s.encode('ascii')
    elif isinstance(s, (bytes, bytearray)):
        s_bytes = bytes(s)
    else:
        raise TypeError("b64u_to_bytes expects str or bytes")
    padding = b'=' * (-len(s_bytes) % 4)
    return base64.urlsafe_b64decode(s_bytes + padding)

def to_camel_case(s):
    if s == 'public_key_credential_params':
        return 'pubKeyCredParams'
    parts = s.split('_')
    return parts[0] + ''.join(p.title() for p in parts[1:])

def convert_to_json_safe(obj):
    # convert bytes -> base64url; fallback to str()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return b64u(bytes(obj))
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return {to_camel_case(k): convert_to_json_safe(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [convert_to_json_safe(i) for i in obj]
    # dataclass / object fallback
    if hasattr(obj, '__dict__'):
        return convert_to_json_safe(obj.__dict__)
    return str(obj)


# ---------------- REGISTER START ----------------
@require_POST
def webauthn_register_start(request):
    """
    Handles the start of the WebAuthn registration process.
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    username = body.get("username")
    display_name = body.get("name", username)
    email = body.get("email")

    if not username:
        return JsonResponse({"error": "Username required"}, status=400)

   
    user_obj, _ = UserProfile.objects.get_or_create(
        email=email, defaults={"username": username}
    )

    user_entity = PublicKeyCredentialUserEntity(
        id=str(user_obj.id).encode("utf-8"), 
        name=username,
        display_name=display_name,
    )

    existing = [{"type": "public-key", "id": c.credential_id}
                for c in user_obj.credentials.all()]

   
    registration_data, state = fido_server.register_begin(
        user=user_entity,
        credentials=existing
    )

    request.session["webauthn_reg_state"] = state
    request.session["webauthn_reg_user_id"] = str(user_obj.id)
    
    options = convert_to_json_safe(registration_data)
    # fido2 library might return 'public_key' as the root key for the options if we are not careful, 
    # but register_begin returns PublicKeyCredentialCreationOptions which has fields like rp, user, etc.
    # Our convert_to_json_safe now converts keys to camelCase.
    # However, PublicKeyCredentialCreationOptions might not be fully compatible with __dict__ access for all versions.
    # Let's verify if we need to manually construct the dict for some fields.
    # For now, relying on __dict__ and camelCase conversion.
    
    print("New Options: ", options)

    return JsonResponse(options)


# ---------------- REGISTER COMPLETE ----------------
@require_POST
def webauthn_register_complete(request):
    body = json.loads(request.body)
    state = request.session.get("webauthn_reg_state")
    user_id = request.session.get("webauthn_reg_user_id")

    if not state or not user_id:
        return JsonResponse({"error": "no registration in progress"}, status=400)

    user_obj = UserProfile.objects.get(id=user_id)

    client = decode_client(body)
    print("Client: ", client)

    try:
        auth_response = AuthenticatorAttestationResponse(
            client['response']['clientDataJSON'],
            client['response']['attestationObject'],
            client['id']
        )
        result = fido_server.register_complete(state, auth_response)
    except Exception as e:
        logger.exception("register_complete failure")
        return JsonResponse({"error": str(e)}, status=400)

    cred = result.credential_data
    print("Result: ", result)

    Credential.objects.create(
        user=user_obj,
        credential_id=cred.credential_id,
        public_key=cred.public_key,
        sign_count=cred.sign_count,
        name=f"Device {Credential.objects.filter(user=user_obj).count() + 1}",
    )

    login(request, user_obj)

    request.session.pop("webauthn_reg_state", None)
    request.session.pop("webauthn_reg_user_id", None)

    return JsonResponse({"status": "ok"})


# ---------------- LOGIN START ----------------
@require_POST
def webauthn_login_start(request):
    body = json.loads(request.body)
    username = body.get("username")

    try:
        user_obj = UserProfile.objects.get(email=username)
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "user not found"}, status=404)

    allow = [{"type": "public-key", "id": c.credential_id}
             for c in user_obj.credentials.all()]

    options, state = fido_server.authenticate_begin(allow)

    request.session["webauthn_auth_state"] = state
    request.session["webauthn_auth_user_id"] = user_obj.id

    return JsonResponse(convert_to_json_safe(options))


# ---------------- LOGIN COMPLETE ----------------
@require_POST
def webauthn_login_complete(request):
    body = json.loads(request.body)
    state = request.session.get("webauthn_auth_state")
    user_id = request.session.get("webauthn_auth_user_id")

    if not state or not user_id:
        return JsonResponse({"error": "no auth in progress"}, status=400)

    user_obj = UserProfile.objects.get(id=user_id)

    client = decode_client(body)

    stored = [{
        "credential_id": c.credential_id,
        "public_key": c.public_key,
        "sign_count": c.sign_count,
    } for c in user_obj.credentials.all()]

    try:
    try:
        auth_response = AuthenticatorAssertionResponse(
            client['response']['clientDataJSON'],
            client['response']['authenticatorData'],
            client['response']['signature'],
            client['id']
        )
        result = fido_server.authenticate_complete(
            state=state,
            credentials=stored,
            response=auth_response,
        )
    except Exception as e:
        logger.exception("auth_complete failure")
        return JsonResponse({"error": str(e)}, status=400)

    # Update counter
    try:
        cred = user_obj.credentials.get(credential_id=result.credential_id)
        cred.sign_count = result.signature_count
        cred.save()
    except:
        pass

    login(request, user_obj)

    request.session.pop("webauthn_auth_state", None)
    request.session.pop("webauthn_auth_user_id", None)

    return JsonResponse({"status": "ok"})
