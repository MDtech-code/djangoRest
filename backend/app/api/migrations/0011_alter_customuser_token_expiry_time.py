# Generated by Django 5.0.6 on 2024-06-05 12:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_alter_customuser_token_expiry_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='token_expiry_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]