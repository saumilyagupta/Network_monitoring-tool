from django.db import models
from datetime import datetime  
from django.utils import timezone

# Create your models here.
class NetworkData(models.Model):
    TimeStamp = models.DateTimeField(blank=True , default=timezone.now())
    Index = models.IntegerField( blank=True, null=True)
    SourceIP = models.GenericIPAddressField( blank=True, null=True)
    SourcePORT = models.IntegerField( blank=True, null=True)
    DestinationIP = models.GenericIPAddressField( blank=True, null=True)
    DestinationPORT = models.IntegerField( blank=True, null=True)
    DataLoad = models.IntegerField(blank=True, null=True)
    PackageType = models.CharField(max_length=6 , blank=True , null=True)



