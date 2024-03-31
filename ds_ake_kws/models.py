# models.py

from django.db import models
from django.contrib.auth.models import User



class EncryptedFile(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_content = models.BinaryField()
    encrypted_symmetric_key = models.BinaryField()
    name = models.CharField(max_length=255)
    content = models.BinaryField()
    private_key = models.BinaryField(null=True, blank=True)
    def __str__(self):
        return self.name
