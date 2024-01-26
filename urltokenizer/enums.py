from django.db.models import TextChoices


class Channel(TextChoices):
    EMAIL = "email", "Email"
    SMS = "sms", "SMS"
