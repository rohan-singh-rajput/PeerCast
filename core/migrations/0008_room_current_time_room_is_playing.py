# Generated by Django 4.2.16 on 2024-11-18 08:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_room_owner'),
    ]

    operations = [
        migrations.AddField(
            model_name='room',
            name='current_time',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='room',
            name='is_playing',
            field=models.BooleanField(default=False),
        ),
    ]
