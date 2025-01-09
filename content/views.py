from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from .models import User,Content, Task, Feedback
from .serializers import UserSerializer, LoginSerializer, SignupSerializer, ContentSerializer, FeedbackSerializer
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import login, logout
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken


class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin

class IsContentWriter(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_content_writer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        if self.action == 'list':
            # Only show content writers to admins for task assignment
            return User.objects.filter(role='CONTENT_WRITER')
        return super().get_queryset()





class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': 'User created successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'message': 'Logged in successfully'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({
            'message': 'Logged out successfully'
        })

class ProfileView(APIView):
    """Get current user's profile"""
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)





# class ContentViewSet(viewsets.ModelViewSet):
#     serializer_class = ContentSerializer
#     permission_classes = [IsAuthenticated]
#     authentication_classes = [SessionAuthentication]

#     def get_queryset(self):
#         user = self.request.user
#         if user:
#             return Content.objects.all()
#         return Content.objects.filter(task__assigned_to=user)

#     def perform_create(self, serializer):
#         serializer.save(created_by=self.request.user)

#     @action(detail=True, methods=['patch'])
#     def state(self, request, pk=None):
#         content = self.get_object()
#         new_status = request.data.get('status')
        
#         if not request.user.is_admin:
#             return Response({"error": "Only admins can update content state"},
#                           status=status.HTTP_403_FORBIDDEN)
            
#         if new_status not in dict(Content.STATUS_CHOICES):
#             return Response({"error": "Invalid status"}, 
#                           status=status.HTTP_400_BAD_REQUEST)
            
#         content.status = new_status
#         content.save()
#         return Response(ContentSerializer(content).data)

#     @action(detail=True, methods=['patch'])
#     def approve(self, request, pk=None):
#         if not request.user.is_admin:
#             return Response({"error": "Only admins can approve content"},
#                           status=status.HTTP_403_FORBIDDEN)
            
#         content = self.get_object()
#         content.status = 'APPROVED'
#         content.save()
#         return Response(ContentSerializer(content).data)


class ContentViewSet(viewsets.ModelViewSet):
    serializer_class = ContentSerializer
    permission_classes = [IsAuthenticated]
   
    def get_queryset(self):
        user = self.request.user
        print("hellonjjjj")
        if user.is_admin:
            return Content.objects.all()
        if user.is_content_writer:
            return Content.objects.filter(task__assigned_to=user)
        return Content.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if user.is_admin or user.is_content_writer:
            serializer.save(created_by=user)
        else:
            raise PermissionDenied("You do not have permission to create content.")

    @action(detail=True, methods=['patch'], permission_classes=[IsAdminUser])
    def state(self, request, pk=None):
        content = self.get_object()
        new_status = request.data.get('status')

        if new_status not in dict(Content.STATUS_CHOICES):
            return Response({"error": "Invalid status"},
                            status=status.HTTP_400_BAD_REQUEST)

        content.status = new_status
        content.last_modified_by = request.user
        content.save()
        return Response(ContentSerializer(content).data)

    @action(detail=True, methods=['patch'], permission_classes=[IsAdminUser])
    def approve(self, request, pk=None):
        content = self.get_object()
        content.status = 'APPROVED'
        content.last_modified_by = request.user
        content.save()
        return Response(ContentSerializer(content).data)


    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def assigned(self, request):
        user = request.user
        if user.is_content_writer:
            queryset = Content.objects.filter(task__assigned_to=user)
            return Response(ContentSerializer(queryset, many=True).data)
        return Response({"error": "Only content writers can view assigned tasks."}, status=status.HTTP_403_FORBIDDEN)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def approved(self, request):
        queryset = Content.objects.filter(status='APPROVED')
        return Response(ContentSerializer(queryset, many=True).data)


class FeedbackViewSet(viewsets.ModelViewSet):
    serializer_class = FeedbackSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        content_id = self.kwargs['content_pk']
        return Feedback.objects.filter(content_id=content_id)

    def perform_create(self, serializer):
        user = self.request.user
        if user.is_admin:
            serializer.save(user=user)
        else:
            raise PermissionDenied("Only admins can provide feedback.")


