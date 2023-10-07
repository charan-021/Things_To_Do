from django.contrib import admin
from .models import To_do_list

# Register your models here.
class myapp_admin(admin.ModelAdmin):
    list_display = ("uqid", "to_do", "isco", "dele",)

admin.site.register(To_do_list, myapp_admin)