# Script to update views.py with trusted visitor access control

import re

# Read the original file
with open('core/views.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Update create_room_view function
old_create_room = r'''@csrf_protect
def create_room_view\(request\):
    if request\.method == 'POST':
        form = RoomForm\(request\.POST\)
        if form\.is_valid\(\):
            room = form\.save\(commit=False\)
            room\.host = request\.user
            room\.video_url = request\.POST\.get\('video_url'\)
            room\.save\(\)
            return redirect\('room_detail', slug=room\.slug\)
        else:
            messages\.error\(request, "Error creating room\."\)
    else:
        form = RoomForm\(\)

    return render\(request, 'app/create_room\.html', \{'form': form\}\)'''

new_create_room = '''@csrf_protect
def create_room_view(request):
    if request.method == 'POST':
        form = RoomForm(request.POST)
        if form.is_valid():
            room = form.save(commit=False)
            room.owner = request.user
            room.host = request.user  # Keep for backward compatibility
            room.video_url = request.POST.get('video_url')
            # Save trusted visitors from cleaned form data
            room.trusted_visitors = form.cleaned_data.get('trusted_visitors', [])
            room.save()
            return redirect('room_detail', slug=room.slug)
        else:
            messages.error(request, "Error creating room.")
    else:
        form = RoomForm()

    return render(request, 'app/create_room.html', {'form': form})'''

content = re.sub(old_create_room, new_create_room, content)

# 2. Update close_room function
old_close_room = r'''@login_required
def close_room\(request, slug\):
    """
    View to close a room\. Only the host of the room can close it\.
    """
    room = get_object_or_404\(Room, slug=slug\)

    if request\.user != room\.host:
        messages\.error\(request, "Only the host can close the room\."\)
        return redirect\('join_room', slug=room\.slug\)

    room\.delete\(\)
    messages\.success\(request, "The room has been successfully closed\."\)
    
    return redirect\('dashboard'\)'''

new_close_room = '''@login_required
def close_room(request, slug):
    """
    View to close a room. Only the owner of the room can close it.
    """
    room = get_object_or_404(Room, slug=slug)

    # Check owner first, fallback to host for backward compatibility
    room_owner = room.owner or room.host
    if request.user != room_owner:
        messages.error(request, "Only the room owner can close the room.")
        return redirect('join_room', slug=room.slug)

    room.delete()
    messages.success(request, "The room has been successfully closed.")
    
    return redirect('dashboard')'''

content = re.sub(old_close_room, new_close_room, content)

# 3. Update join_room_view function
old_join_room = r'''@login_required
def join_room_view\(request, slug\):
    room = get_object_or_404\(Room, slug=slug\)
    
    if request\.user not in room\.participants\.all\(\):
        room\.participants\.add\(request\.user\)
        room\.save\(\)
    
    context = \{
        'room': room,
    \}
    return render\(request, 'app/join_room\.html', context\)'''

new_join_room = '''@login_required
def join_room_view(request, slug):
    room = get_object_or_404(Room, slug=slug)
    
    # Check if user is allowed to access this room
    if not room.is_visitor_allowed(request.user):
        messages.error(
            request, 
            "Access denied. You are not on the trusted visitor list for this room."
        )
        return render(request, 'app/access_denied.html', {
            'room': room,
            'owner_email': room.owner.email if room.owner else (room.host.email if room.host else 'Unknown')
        })
    
    if request.user not in room.participants.all():
        room.participants.add(request.user)
        room.save()
    
    context = {
        'room': room,
        'is_owner': request.user == (room.owner or room.host),
    }
    return render(request, 'app/join_room.html', context)'''

content = re.sub(old_join_room, new_join_room, content)

# Write the updated content
with open('core/views.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("views.py updated successfully!")
