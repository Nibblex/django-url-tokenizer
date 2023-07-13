from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .tokenizer import Tokenizer


class SendTokenSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, email):
        self.user = get_object_or_404(get_user_model(), email=email)
        return email

    def create(self, validated_data):
        token_type = self.context["view"].kwargs["type"]

        uidb64, token, link, sent = self.user.generate_tokenized_link(
            token_type, send_email=True
        )
        if not sent:
            raise serializers.ValidationError(_("could not send email"))

        return validated_data


class CheckTokenSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    extra_data = serializers.JSONField(required=False, write_only=True)

    def create(self, validated_data):
        token_type = self.context["view"].kwargs["type"]
        tokenizer = Tokenizer(token_type)

        user = tokenizer.check_token(
            validated_data["uidb64"],
            validated_data["token"],
            **validated_data.get("extra_data", {})
        )

        if not user:
            raise AuthenticationFailed(_("invalid token"))

        return validated_data
