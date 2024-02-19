from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
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

    def validate(self, data):
        email, phone = data.get("email"), data.get("phone")
        if not email and not phone:
            raise serializers.ValidationError(
                _("Either 'email' or 'phone' is required for sending token.")
            )

        email_field = from_config(SETTINGS, "email_field", "email")
        phone_field = from_config(SETTINGS, "phone_field", "phone")

        self.context["user"] = get_object_or_404(
            User, **{email_field: email} if email else {phone_field: phone}
        )

        return data

    def create(self, validated_data):
        view = self.context["view"]
        assert "type" in view.kwargs, _(
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_field` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        tokenizer = URLTokenizer(view.kwargs["type"])
        user = self.context.get("user")
        channel = validated_data.get("channel")

        url_token = tokenizer.generate_tokenized_link(
            user, channel=channel, fail_silently=True
        )
        if url_token.exception:
            raise serializers.ValidationError(url_token.exception)

        return validated_data


class CheckTokenSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    callbacks_kwargs = serializers.JSONField(required=False, write_only=True)
    callbacks_returns = serializers.JSONField(read_only=True)
    user_data = serializers.JSONField(required=False, default=dict)

    def create(self, validated_data):
        view = self.context["view"]
        assert "type" in view.kwargs, _(
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_field` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        tokenizer = URLTokenizer(view.kwargs["type"])

        uidb64 = validated_data["uidb64"]
        token = validated_data["token"]
        user_data = validated_data["user_data"]
        callback_kwargs = validated_data.get("callbacks_kwargs", {})

        user, log = tokenizer.check_token(uidb64, token, user_data, fail_silently=True)
        if not user:
            raise serializers.ValidationError(
                _("The token is invalid or has expired. Please request a new one.")
            )

        callbacks_returns = tokenizer.run_callbacks(
            user, callback_kwargs=callback_kwargs, fail_silently=True
        )

        validated_data["callbacks_returns"] = callbacks_returns

        return validated_data
