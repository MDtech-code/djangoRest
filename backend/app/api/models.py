
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class CustomUser(AbstractUser):
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=500, null=True, blank=True)
    token_created_at = models.DateTimeField(null=True, blank=True)
    token_expiry_time = models.DateTimeField(null=True, blank=True)

    def is_token_valid(self):
        if self.verification_token and self.token_created_at:
            return timezone.now() < self.token_expiry_time
        return False


class BlogPost(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    published_date = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='blog_images/', null=True, blank=True)
    author = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.title
