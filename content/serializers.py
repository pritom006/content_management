from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User

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
        user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if not user:
            raise serializers.ValidationError('Invalid credentials')
        if not user.is_active:
            raise serializers.ValidationError('Account is disabled')
        attrs['user'] = user
        return attrs



