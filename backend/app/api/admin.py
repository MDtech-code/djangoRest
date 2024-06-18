from django.contrib import admin
from .models import BlogPost,CustomUser
# Register your models here.
admin.site.register(BlogPost)
admin.site.register(CustomUser)