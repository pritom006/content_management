from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractUser, Group, Permission


class User(AbstractUser):
    ROLE_CHOICES = (
        ('SUPERADMIN', 'Super Admin'),
        ('MANAGER', 'Manager'),
        ('CONTENT_WRITER', 'Content Writer'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    
    # To avoid conflicts with auth.User
    groups = models.ManyToManyField('auth.Group', related_name='content_users')
    user_permissions = models.ManyToManyField('auth.Permission', related_name='content_users')

    class Meta:
        db_table = 'users'
        
    def save(self, *args, **kwargs):
        if self.is_superuser:
            self.role = 'SUPERADMIN'
        super().save(*args, **kwargs)

    
    @property
    def is_admin(self):
        return self.role in ['SUPERADMIN', 'MANAGER']

    @property
    def is_content_writer(self):
        return self.role == 'CONTENT_WRITER'



class Content(models.Model):
    STATUS_CHOICES = (
        ('DRAFT', 'Draft'),
        ('ASSIGNED', 'Assigned'),
        ('PENDING_REVIEW', 'Pending Review'),
        ('APPROVED', 'Approved'),
    )
    
    title = models.CharField(max_length=200)
    content = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ASSIGNED')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='created_content'
    )
    last_modified_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='modified_content'
    )

    class Meta:
        db_table = 'content'

    @property
    def is_editable(self):
        return self.status != 'APPROVED'

    def can_edit(self, user):
        if self.status == 'APPROVED':
            return False
        if user.is_admin:
            return True
        return user.is_content_writer and hasattr(self, 'task') and self.task.assigned_to == user


class Task(models.Model):
    content = models.OneToOneField(Content, on_delete=models.CASCADE, related_name='task')
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assigned_tasks')
    assigned_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tasks')
    assigned_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        if self.assigned_to.role != 'CONTENT_WRITER':
            raise ValidationError("Tasks can only be assigned to content writers")
        if self.assigned_by.role not in ['SUPERADMIN', 'MANAGER']:
            raise ValidationError("Only managers and super admins can assign tasks")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'tasks'

class Feedback(models.Model):
    content = models.ForeignKey(Content, on_delete=models.CASCADE, related_name='feedbacks')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        if self.user.role not in ['SUPERADMIN', 'MANAGER']:
            raise ValidationError("Only managers and super admins can provide feedback")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    class Meta:
        db_table = 'feedback'

