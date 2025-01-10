from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .views import CustomTokenObtainPairView


urlpatterns = [
    
    path('users/', views.UserViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('auth/signup/', views.SignupView.as_view(), name='auth_signup'),
    path('auth/login/', views.LoginView.as_view(), name='auth_login'),
    #path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    #path('auth/login/', CustomTokenObtainPairView.as_view(), name='auth_login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', views.LogoutView.as_view(), name='auth_logout'),
    path('auth/profile/', views.ProfileView.as_view(), name='auth_profile'),


    # Content Management URLs
    path('content/', views.ContentViewSet.as_view({
        'get': 'list',
        'post': 'create'
    }), name='content-list'),
    path('content/<int:pk>/', views.ContentViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='content-detail'),
    path('content/<int:pk>/state/', views.ContentViewSet.as_view({
        'get': 'retrieve',
        'patch': 'state'
    }), name='content-state'),
    path('content/<int:pk>/approve/', views.ContentViewSet.as_view({
        'patch': 'approve'
    }), name='content-approve'),

    # Feedback URLs
    path('content/<int:content_pk>/feedback/', views.FeedbackViewSet.as_view({
        'get': 'list',
        'post': 'create'
    }), name='content-feedback'),
    
    #Task URLs
    path('tasks/', views.TaskViewSet.as_view({
        'get': 'list',
        'post': 'create'
    }), name='task-list'),
    path('tasks/<int:pk>/', views.TaskViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='task-detail'),
]