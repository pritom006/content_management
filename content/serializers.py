from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, Task, Content, Feedback
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'first_name', 'last_name')
        read_only_fields = ('role',)


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2', 'first_name', 'last_name', 'role')
        extra_kwargs = {
            'email': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # Only SUPERADMIN can create MANAGER accounts
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            if attrs['role'] == 'MANAGER' and request.user.role != 'SUPERADMIN':
                raise serializers.ValidationError({
                    "role": "Only Super Admins can create Manager accounts"
                })
            if attrs['role'] == 'SUPERADMIN':
                raise serializers.ValidationError({
                    "role": "SUPERADMIN role cannot be assigned during signup"
                })
        else:
            # For unauthenticated signups, only allow CONTENT_WRITER role
            if attrs['role'] != 'CONTENT_WRITER':
                raise serializers.ValidationError({
                    "role": "New users can only sign up as Content Writers"
                })
        
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.password = make_password(password)
        user.save()
        return user

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password')

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            try:
                user = User.objects.get(username=username)
                if user.check_password(password):
                    if not user.is_active:
                        raise serializers.ValidationError({
                            'error': 'Account is disabled.'
                        })
                    attrs['user'] = user
                    return attrs
                else:
                    raise serializers.ValidationError({
                        'error': 'Incorrect password.'
                    })
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    'error': 'User does not exist.'
                })
        raise serializers.ValidationError({
            'error': 'Must include username and password.'
        })





class ContentSerializer(serializers.ModelSerializer):
    feedbacks = serializers.SerializerMethodField()
    
    class Meta:
        model = Content
        fields = ['id', 'title', 'content', 'status', 'created_at', 'updated_at', 
                 'created_by', 'last_modified_by', 'feedbacks']
        read_only_fields = ['created_by', 'last_modified_by', 'status']

    def get_feedbacks(self, obj):
        return FeedbackSerializer(obj.feedbacks.all(), many=True).data

    def create(self, validated_data):
        user = self.context['request'].user
        validated_data['created_by'] = user
        validated_data['last_modified_by'] = user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data['last_modified_by'] = self.context['request'].user
        return super().update(instance, validated_data)



class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = ['id', 'content', 'user', 'comment', 'created_at']
        read_only_fields = ['user', 'created_at']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)

