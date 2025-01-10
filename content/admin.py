from django.contrib import admin
from .models import User, Content, Task, Feedback


class ContentAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # Object is being created
            obj.created_by = request.user
        obj.last_modified_by = request.user
        super().save_model(request, obj, form, change)

# Register your models here.
admin.site.register(User)
admin.site.register(Content, ContentAdmin)
admin.site.register(Task)
admin.site.register(Feedback)