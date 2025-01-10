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


# class SignupSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True, required=True)
#     role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=True)

#     class Meta:
#         model = User
#         fields = ('username', 'email', 'password', 'first_name', 'last_name', 'role')
#         extra_kwargs = {
#             'email': {'required': True}
#         }

#     def validate(self, attrs):

#         # Only SUPERADMIN can create MANAGER accounts
#         request = self.context.get('request')
    
#             # For unauthenticated signups, only allow CONTENT_WRITER role
#         attrs['role'] = 'CONTENT_WRITER'
                
#         attrs["password"] = make_password(attrs["password"])
#         return attrs


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
            if attrs['role'] != 'CONTENT_WRITER':
                raise serializers.ValidationError({
                    "role": "New users can only sign up as Content Writers"
                })
        del  attrs['password2']
        return attrs

    # def create(self, validated_data):
    #     validated_data["password"] = make_password(validated_data["password"])
    #     print("password==>", validated_data["password"])
    #     return validated_data
     

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        
        instance.is_active = True
        if password is not None:
            # Set password does the hash, so you don't need to call make_password 
            instance.set_password(password)
        instance.save()
        return instance

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
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    'error': 'User does not exist.'
                })
            
            if not user.check_password(password):
                raise serializers.ValidationError({
                    'error': 'Incorrect password.'
                })
                
            if not user.is_active:
                raise serializers.ValidationError({
                    'error': 'Account is disabled.'
                })
                
            attrs['user'] = user
            return attrs

        raise serializers.ValidationError({
            'error': 'Must include username and password.'
        })




# class ContentSerializer(serializers.ModelSerializer):
#     feedbacks = serializers.SerializerMethodField()
    
#     class Meta:
#         model = Content
#         fields = ['id', 'title', 'content', 'status', 'created_at', 'updated_at', 
#                  'created_by', 'last_modified_by', 'feedbacks']
#         read_only_fields = ['created_by', 'last_modified_by', 'status']

#     def get_feedbacks(self, obj):
#         return FeedbackSerializer(obj.feedbacks.all(), many=True).data

#     def create(self, validated_data):
#         user = self.context['request'].user
#         validated_data['created_by'] = user
#         validated_data['last_modified_by'] = user
#         return super().create(validated_data)

#     def update(self, instance, validated_data):
#         validated_data['last_modified_by'] = self.context['request'].user
#         return super().update(instance, validated_data)


class ContentSerializer(serializers.ModelSerializer):
    feedbacks = serializers.SerializerMethodField()
    
    class Meta:
        model = Content
        fields = ['id', 'title', 'content', 'status', 'created_at', 'updated_at', 'feedbacks']
        #read_only_fields = ['created_by', 'last_modified_by', 'status']

    def get_feedbacks(self, obj):
        return FeedbackSerializer(obj.feedbacks.all(), many=True).data

    def create(self, validated_data):
        # Handle cases where user might not be available
        validated_data['created_by'] = None
        validated_data['last_modified_by'] = None
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data['last_modified_by'] = None
        return super().update(instance, validated_data)


# class FeedbackSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Feedback
#         fields = ['id', 'content', 'user', 'comment', 'created_at']
#         read_only_fields = ['user', 'created_at']

#     def create(self, validated_data):
#         validated_data['user'] = self.context['request'].user
#         return super().create(validated_data)

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = ['id', 'content', 'user', 'comment', 'created_at']
        read_only_fields = ['user', 'created_at']

    def create(self, validated_data):
        # Handle cases where user might not be available
        validated_data['user'] = None
        return super().create(validated_data)


class TaskSerializer(serializers.ModelSerializer):
    content = ContentSerializer(read_only=True)
    content_id = serializers.PrimaryKeyRelatedField(
        queryset=Content.objects.all(),
        source='content',
        write_only=True
    )
    assigned_to_name = serializers.CharField(source='assigned_to.username', read_only=True)
    assigned_by_name = serializers.CharField(source='assigned_by.username', read_only=True)

    class Meta:
        model = Task
        fields = ('id', 'content', 'content_id', 'assigned_to', 'assigned_to_name',
                 'assigned_by', 'assigned_by_name', 'assigned_at')
        read_only_fields = ('assigned_by',)

    def create(self, validated_data):
        # Handle cases where user might not be available
        validated_data['assigned_by'] = None
        return super().create(validated_data)