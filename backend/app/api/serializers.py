
from django.contrib.auth import authenticate
from django.utils.crypto import get_random_string
import jwt
import datetime

from .models import BlogPost
#! this apprach have less code but on this code i have less control
from rest_framework import serializers
from .models import CustomUser
from app.api.utils.form_validation import validation_username, validation_email, validation_password
from app.api.utils.verification_token import generate_verification_token
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail

class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'password', 'email']
        # it hide the password during the deserilization
        extra_kwargs = {
            'password': {'write_only': True}
        }
    #! validate upcoming data fro avoiding beginner error
    
    def validate_username(self, value):
        
        # Use your custom validation function
        username_validation_error = validation_username(value)
        if username_validation_error:
            raise serializers.ValidationError(username_validation_error['response'])
        
       # Check if the username already exists.
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_email(self, value):
        
         # Use your custom validation function
        email_validation_error = validation_email(value)
        if email_validation_error:
            raise serializers.ValidationError(email_validation_error['response']) 
        #Check if the email already exists.
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_password(self, value):
        # Use your custom validation function
        password_validation_error = validation_password(value)
        if password_validation_error:
            raise serializers.ValidationError(password_validation_error['response'])
        return value


    #! this creates function override the previous one
    def create(self, validate_data, user=None):
        user =CustomUser(
            username=validate_data['username'],
            email=validate_data['email']
        )
        user.set_password(validate_data['password'])
        user.save()

        # Generate a new verification token 
        token =generate_verification_token(user.pk)
        print(token)
        user.verification_token =token
        user.token_created_at = timezone.now()  # Set the token creation time
        user.save()
        #! send the verification email
        verification_link = f"{settings.FRONTEND_URL}/verify_email/?token={token}"
        send_mail(
        	    'Email Verification Request',
        	    f"Here is your email verification link: {verification_link}",
        	    settings.EMAIL_HOST_USER,
        	    [user.email],
        	)
        
        
        return user 

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError('Invalid credentials')

        

        user = authenticate(username=username, password=password)
        if user:
            if not user.email_verified == True:
             token = generate_verification_token(user.pk)
             user.verification_token = token
             user.token_created_at = timezone.now() 
             user.token_expiry_time = timezone.now() + datetime.timedelta(minutes=1)  # Set the token expiry time
             user.save()
 
             verification_link = f"{settings.FRONTEND_URL}/verify_email/?token={token}"
             send_mail(
                 'Email Verification Request',
                 f"Here is your email verification link: {verification_link}",
                 settings.EMAIL_HOST_USER,
                 [user.email],
             )
        else:
            raise serializers.ValidationError('Invalid credentials')

        data['user'] = user
        return data
    



class BlogPostSerializer(serializers.ModelSerializer):

    author = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())

    class Meta:
        model =BlogPost
        fields = ['id', 'title', 'content', 'published_date', 'image', 'author']

    def create(self, validated_data):
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)


#! this approach have more code but on this code i have more control

'''
class BlogPostSerializer(serializers.Serializer):
    tittle = serializers.CharField(max_length=100)
    content = serializers.CharField()
    published_date = serializers.DateTimeField()

    def create(self, validated_data):
        return BlogPost.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.tittle = validated_data.get('tittle', instance.tittle)
        instance.content = validated_data.get('content', instance.content)
        instance.published_date = validated_data.get('published_date', instance.published_date)
        instance.save()
        return instance
'''
