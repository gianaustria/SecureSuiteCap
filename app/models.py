from django.db import models
from django.contrib.auth.models import User

class ScanLog(models.Model):
    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    stats = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_logs', null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)  # For unauthenticated users

    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{self.filename} - {self.status} by {user_str}"

class CollaborationMessage(models.Model):
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Message at {self.timestamp}"

class Policy(models.Model):
    category = models.CharField(max_length=50)
    extensions = models.CharField(max_length=255, default='.exe,.dll,.pdf,.txt,.docx,.eml')
    keywords = models.TextField(default='order\ndocument\nurgent\nlogin\npassword\naccount\nfree\noffer\ndiscount')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Policy {self.category} updated at {self.updated_at}"