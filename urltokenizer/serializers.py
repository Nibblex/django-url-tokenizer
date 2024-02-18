from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework import serializers

from .enums import Channel
from .tokenizer import URLTokenizer
from .utils import SETTINGS, from_config


User = get_user_model()


class ChannelSerializer(serializers.Serializer):
    channel = serializers.ChoiceField(
        choices=Channel.choices, required=True, allow_blank=False
    )


class SendTokenSerializer(ChannelSerializer):
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)

    def __init__(self, *args, **kwargs):
        view = self.context["view"]
        assert "type" in view.kwargs, (
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_field` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        super().__init__(*args, **kwargs)

    def validate(self, data):
        if not data.get("email") and not data.get("phone"):
            raise serializers.ValidationError(
                "Either 'email' or 'phone' is required for sending token."
            )

        return data

    def create(self, validated_data):
        view = self.context["view"]
        email_field = from_config(SETTINGS, "email_field", "email")
        phone_field = from_config(SETTINGS, "phone_field", "phone")

        channel = validated_data.get("channel")
        email = validated_data.get("email")
        phone = validated_data.get("phone")

        user = self.context.get("user")
        user = user or get_object_or_404(
            User, **{email_field: email} if email else {phone_field: phone}
        )

        tokenizer = URLTokenizer(view.kwargs["type"])

        url_token = tokenizer.generate_tokenized_link(
            user, channel=channel, fail_silently=True
        )
        if url_token.exception:
            raise serializers.ValidationError(url_token.exception)

        return validated_data
