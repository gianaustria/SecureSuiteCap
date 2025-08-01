from django.db import models

class ScanLog(models.Model):
    filename = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    stats = models.JSONField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.filename} - {self.status}"

class CollaborationMessage(models.Model):
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

class Policy(models.Model):
    category = models.CharField(max_length=50)