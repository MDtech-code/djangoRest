from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView
urlpatterns = [
    #! simple api and function base drf  url 
 #path('signup/',views.Signup_views,name="signup"),
 #path('login/',views.login_views,name='login'),
 #path('logout/',views.logout_views,name='logout'),
    #! class base drf url
 path('csrfToken/',views.csrf_token_views,name='csrf_token'),
 path('signup/',views.SignupViewDRF.as_view(),name='signup'),
 path('login/',views.LoginViewDRF.as_view(),name='login'),
 path('logout/',views.LogoutViewDRF.as_view(),name='logout'),
 path('blogpost/',views.CreateBlogPostViews.as_view(),name="blogPost"),
 path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
 path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
 path('forget_password/',views.ForgetPasswordViews.as_view(),name='forget-password'),
 path('reset_password/',views.ResetPasswordView.as_view(),name='reset-password'),
 path('email-verify-request/',views.SendEmailVerificationView.as_view(),name='email-verify-request'),
 #path('blogposts/',views.create_blog_post_views,name='blogPost'),
]
