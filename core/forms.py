from django import forms
from .models import Room

class RoomForm(forms.ModelForm):
    trusted_visitors = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'rows': 3,
            'placeholder': 'alice@example.com, bob@example.com',
            'class': 'w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent'
        }),
        help_text="Enter email addresses separated by commas. Only these users will be allowed to join.",
        label="Trusted Visitors"
    )
    
    class Meta:
        model = Room
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-900 focus:border-transparent',
                'placeholder': 'Enter room name'
            })
        }
    
    def clean_trusted_visitors(self):
        """Validate and clean the trusted visitors field"""
        data = self.cleaned_data.get('trusted_visitors', '')
        if not data:
            return []
        
        # Split by comma and clean up whitespace
        emails = [email.strip() for email in data.split(',') if email.strip()]
        
        # Basic email validation
        import re
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        invalid_emails = [email for email in emails if not email_pattern.match(email)]
        if invalid_emails:
            raise forms.ValidationError(
                f"Invalid email address(es): {', '.join(invalid_emails)}"
            )
        
        return emails