# Generated by Django 3.1.2 on 2021-01-11 11:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_auto_20210109_1316'),
    ]

    operations = [
        migrations.AddField(
            model_name='authkeys',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
