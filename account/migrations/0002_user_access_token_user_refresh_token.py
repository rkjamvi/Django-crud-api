# Generated by Django 4.2.9 on 2024-02-21 09:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='access_token',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='refresh_token',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
