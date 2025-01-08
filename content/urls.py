from django.urls import path
from . import views



urlpatterns = [
    path('users/', views.UserViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('auth/signup/', views.SignupView.as_view(), name='auth_signup'),
    path('auth/login/', views.LoginView.as_view(), name='auth_login'),
    path('auth/logout/', views.LogoutView.as_view(), name='auth_logout'),
    path('auth/profile/', views.ProfileView.as_view(), name='auth_profile'),
]