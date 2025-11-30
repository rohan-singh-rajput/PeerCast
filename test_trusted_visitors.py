
import os
import django
from django.conf import settings

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'peercast.settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from core.models import Room
from core.views import create_room_view, join_room_view
from core.forms import RoomForm

User = get_user_model()

def test_trusted_visitors():
    print("Setting up test data...")
    # Create users
    owner = User.objects.create_user(username='owner', email='owner@example.com', password='password')
    alice = User.objects.create_user(username='alice', email='alice@example.com', password='password')
    bob = User.objects.create_user(username='bob', email='bob@example.com', password='password')
    charlie = User.objects.create_user(username='charlie', email='charlie@other.com', password='password')

    print("Testing RoomForm validation...")
    # Test valid form with trusted visitors
    form_data = {
        'name': 'Test Room',
        'trusted_visitors': 'alice@example.com, bob@example.com'
    }
    form = RoomForm(data=form_data)
    if form.is_valid():
        print("Form is valid.")
        print(f"Cleaned trusted_visitors: {form.cleaned_data['trusted_visitors']}")
    else:
        print(f"Form errors: {form.errors}")

    print("\nTesting Room creation logic...")
    # Simulate room creation
    room = Room(name="Test Room", owner=owner, host=owner)
    room.trusted_visitors = ['alice@example.com', 'bob@example.com']
    room.save()
    print(f"Room created: {room.name} (ID: {room.id})")
    print(f"Trusted visitors: {room.trusted_visitors}")

    print("\nTesting Access Control...")
    
    # Test Owner Access
    if room.is_visitor_allowed(owner):
        print("PASS: Owner allowed")
    else:
        print("FAIL: Owner denied")

    # Test Alice Access (Allowed)
    if room.is_visitor_allowed(alice):
        print("PASS: Alice allowed")
    else:
        print("FAIL: Alice denied")

    # Test Charlie Access (Denied)
    if not room.is_visitor_allowed(charlie):
        print("PASS: Charlie denied")
    else:
        print("FAIL: Charlie allowed")

    print("\nTesting Open Room (No trusted visitors)...")
    open_room = Room.objects.create(name="Open Room", owner=owner, host=owner)
    if open_room.is_visitor_allowed(charlie):
        print("PASS: Charlie allowed in open room")
    else:
        print("FAIL: Charlie denied in open room")

    # Cleanup
    room.delete()
    open_room.delete()
    owner.delete()
    alice.delete()
    bob.delete()
    charlie.delete()
    print("\nTest completed.")

if __name__ == "__main__":
    try:
        test_trusted_visitors()
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
