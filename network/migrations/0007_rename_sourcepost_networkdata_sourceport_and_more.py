# Generated by Django 4.1.13 on 2024-07-17 12:18

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network', '0006_delete_roomtest_networkdata_destinationport_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='networkdata',
            old_name='SourcePOST',
            new_name='SourcePORT',
        ),
        migrations.AlterField(
            model_name='networkdata',
            name='TimeStamp',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2024, 7, 17, 17, 48, 33, 195313)),
        ),
    ]
