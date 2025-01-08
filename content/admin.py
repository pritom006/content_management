from django.contrib import admin
from .models import User, Content, Task, Feedback

# Register your models here.
admin.site.register(User)
admin.site.register(Content)
admin.site.register(Task)
admin.site.register(Feedback)