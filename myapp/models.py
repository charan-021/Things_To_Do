# Create your models here.
from django.db import models

class To_do_list(models.Model):
    uqid = models.CharField(max_length=50)
    to_do = models.CharField(max_length=150)
    dele = models.BooleanField(default=False)
    isco = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.uqid}"