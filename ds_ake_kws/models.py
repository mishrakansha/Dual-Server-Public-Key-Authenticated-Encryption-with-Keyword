# models.py

from django.db import models
from django.contrib.auth.models import User
import os
import uuid

def upload_to_original(instance, filename):
    original_filename = filename
    unique_identifier = uuid.uuid4().hex
    file_extension = os.path.splitext(original_filename)[1]
    unique_filename = f"{unique_identifier}{file_extension}"
    upload_path = "upload"
    return os.path.join(upload_path, unique_filename)


class EncryptedFile(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_content = models.BinaryField()
    encrypted_symmetric_key = models.BinaryField()
    name = models.CharField(max_length=255)
    content = models.BinaryField()
    private_key = models.BinaryField(null=True, blank=True)
    fileType = models.CharField(max_length=225)
    file = models.FileField(upload_to=upload_to_original)

    def __str__(self):
        return self.name
