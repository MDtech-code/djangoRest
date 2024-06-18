from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view,permission_classes,authentication_classes
from rest_framework import generics, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import BlogPost,CustomUser
from .serializers import BlogPostSerializer,CustomUserSerializer,LoginSerializer
import json
from django.http import JsonResponse,HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.images import ImageFile
from django.core import serializers
from django.contrib.auth import authenticate,login,logout
from datetime import timedelta
from django.utils import timezone
from django.utils.decorators import method_decorator
import jwt
from django.conf import settings
from app.api.utils.verification_token import generate_verification_token
from django.core.mail import send_mail
from app.api.utils.form_validation import validation_email,validation_password
from app.api.utils.send_email import send_email
import datetime
from django.middleware.csrf import get_token


#! this view help to send csrf token to frontend
@api_view(['GET'])
def csrf_token_views(request):
    try:
        csrf_token = get_token(request)
        response=Response({'csrfToken': csrf_token})
        response.set_cookie('csrftoken',csrf_token,max_age=31449600,secure=True,httponly=True,samesite='None')
        return response
    except Exception as e:
        return Response({'responseErrorMessage': str(e)}, status=500)

#! reqeust.user      
#! class base views DRF
# @method_decorator(csrf_exempt, name='dispatch')

class SignupViewDRF(APIView):
    def post(self,request):
        data=request.data
        serializer = CustomUserSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'responseMessage': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginViewDRF(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)

            # Create tokens using SimpleJWT
            refresh = RefreshToken.for_user(user)
            print(str(refresh))
            response=  Response({
                'access': str(refresh.access_token),
                'loginuser': user.username,
                'response': 'Login successful',
            }, status=status.HTTP_200_OK)
            response.set_cookie('refresh_token', str(refresh), httponly=True, samesite='None')
            return response

        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
'''   
@method_decorator(csrf_exempt, name='dispatch')
class LoginViewDRF(APIView):
    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                        'token': token.key,
	    			    'loginuser': user.username,
	    			    'response': 'Login successful',
	    			}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_400_BAD_REQUEST)
   ''' 

#@method_decorator(csrf_exempt, name='dispatch')
class LogoutViewDRF(APIView):
    def post(self, request):
        logout(request)
        return Response({'responseMessage': 'Logout successful'}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class SendEmailVerificationView(APIView):
    def post(self, request):
        user = request.user
        if not user.email_verified == True:
            try:
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
                return Response({'message': 'Verification email sent successfully'}, status=status.HTTP_200_OK)
            except Exception as e:
                # Log the error or send it back as a response
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'message': 'Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)
        

class VerifyEmailView(APIView):
    def get(self, request):
        token = request.query_params.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = CustomUser.objects.get(pk=payload['user_id'])
             # Check if the token has expired
            if not user.is_token_valid():
                return Response({"response": "Token has expired"}, status=status.HTTP_403_FORBIDDEN)

            if user:
                user.email_verified = True
                user.save()
                return Response({'response': "Email has been verified successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"response": "Invalid user ID"}, status=status.HTTP_403_FORBIDDEN)
        except (jwt.ExpiredSignatureError, jwt.DecodeError, CustomUser.DoesNotExist):
            return Response({"response": "Invalid token"}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({'response': f"Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ForgetPasswordViews(APIView):
    def post(self,request,*args,**kwargs):
        email=request.data.get('email',None)
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        # Use the CustomUserSerializer for validation and uniqueness checks
        email_error=validation_email(email)
        if email_error:
            return Response (email_error,status=status.HTTP_403_FORBIDDEN)

        
        try:
            user = CustomUser.objects.filter(email=email).first()
            if user:
               token=generate_verification_token(user.pk)
               password_reset_link = f"{settings.FRONTEND_URL}/reset_password/?token={token}"
               
               send_mail(
                   'Password Reset Request',
                   f"Here is your password reset link: {password_reset_link}",
                   settings.EMAIL_HOST_USER,
                   [email],
               )
               return Response({'response': "Password reset link has been sent"},status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
             return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


@method_decorator(csrf_exempt, name='dispatch')
class ResetPasswordView(APIView):
    def post(self,request):
        data=request.data
        new_password=data.get('password',None)
        token=data.get('token',None)
        if not new_password:
            return Response({'error': 'password  is required'}, status=status.HTTP_400_BAD_REQUEST)
        # Use the CustomUserSerializer for validation and uniqueness checks
        password_error=validation_password(new_password)
        if password_error:
            return Response (password_error,status=status.HTTP_403_FORBIDDEN)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = CustomUser.objects.get(pk=payload['user_id'])
            
        except (jwt.ExpiredSignatureError, jwt.DecodeError, CustomUser.DoesNotExist):
            return Response({"response": "Invalid token"},status=status.HTTP_403_FORBIDDEN)
        if user:
                user.set_password(new_password)
                user.save()
                return Response({'response': "Password has been reset successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"response": "Invalid user ID"}, status=status.HTTP_403_FORBIDDEN)








#! class base views
@method_decorator(csrf_exempt, name='dispatch')
class CreateBlogPostViews(APIView):
    #authenticate_classes=[TokenAuthentication]
    permission_classes=[IsAuthenticated]
    def post(self,request):
        if request.method == 'POST':
            data=request.data
            serializers = BlogPostSerializer(data=data, context={'request': request})

            if serializers.is_valid():
                serializers.save()
                return Response(serializers.data, status=status.HTTP_201_CREATED)
            return Response(serializers._errors, status=status.HTTP_400_BAD_REQUEST)

