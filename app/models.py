from django.db import models

class ScanLog(models.Model):
    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)

class CollaborationMessage(models.Model):
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

class Policy(models.Model):
    category = models.CharField(max_length=50)
