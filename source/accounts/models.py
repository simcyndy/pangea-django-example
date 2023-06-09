from django.db import models
from django.contrib.auth.models import User


class Activation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    code = models.CharField(max_length=20, unique=True)
    email = models.EmailField(blank=True)

class Document(models.Model):
   file = models.FileField(upload_to='documents/')
   uploaded_at = models.DateTimeField(auto_now_add=True)
   checksum = models.CharField(max_length=64)
   uploaded_at = models.DateTimeField(auto_now_add=True)
   user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)