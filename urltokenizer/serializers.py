from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _

from .enums import Channel
from .exceptions import URLTokenizerError
from .models import Log
from .tokenizer import URLTokenizer
from .utils import SETTINGS, _from_config

User = get_user_model()


EMAIL_FIELD = _from_config(SETTINGS, "email_field", "email")
PHONE_FIELD = _from_config(SETTINGS, "phone_field", "phone")


class ChannelSerializer(serializers.Serializer):
    channel = serializers.ChoiceField(choices=Channel.choices, required=True)


class SendTokenSerializer(ChannelSerializer):
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)
    log = serializers.PrimaryKeyRelatedField(read_only=True)

    def validate(self, data):
        email, phone = data.get("email"), data.get("phone")
        if not email and not phone:
            raise serializers.ValidationError(
                _("Either 'email' or 'phone' is required for sending token.")
            )

        # user lookup

        self.context["user"] = get_object_or_404(
            User, **{EMAIL_FIELD: email} if email else {PHONE_FIELD: phone}
        )

        return data

    def create(self, validated_data):
        view = self.context["view"]

        token_type_url_kwarg = getattr(view, "token_type_url_kwarg", "type")
        assert token_type_url_kwarg in view.kwargs, _(
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_url_kwarg` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        tokenizer = URLTokenizer(view.kwargs[token_type_url_kwarg])

        channel = validated_data.get("channel")

        # send token

        url_token = tokenizer.generate_tokenized_link(
            self.context.get("user"),
            path=self.context.get("path"),
            domain=self.context.get("domain"),
            protocol=self.context.get("protocol"),
            port=self.context.get("port"),
            channel=channel,
            template=self.context.get("template"),
            email_subject=self.context.get("email_subject"),
            fail_silently=self.context.get("fail_silently"),
        )

        validated_data["log"] = url_token.log

        if url_token.precondition_failed:
            raise AuthenticationFailed(_("precondition failed"))

        if url_token.exception:
            raise serializers.ValidationError(url_token.exception)

        return validated_data


class BulkSendTokenSerializer(ChannelSerializer):
    emails = serializers.ListField(
        child=serializers.EmailField(), required=False, write_only=True
    )
    phones = serializers.ListField(
        child=serializers.CharField(), required=False, write_only=True
    )
    sent = serializers.JSONField(read_only=True, default=dict)
    precondition_failed = serializers.JSONField(read_only=True, default=dict)
    errors = serializers.JSONField(read_only=True, default=dict)

    def create(self, validated_data):
        view = self.context["view"]

        token_type_url_kwarg = getattr(view, "token_type_url_kwarg", "type")
        assert token_type_url_kwarg in view.kwargs, _(
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_url_kwarg` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        tokenizer = URLTokenizer(view.kwargs[token_type_url_kwarg])

        channel = validated_data.get("channel")

        # users lookup

        users = self.context.get("users")
        emails, phones = validated_data.get("emails"), validated_data.get("phones")
        users = users or User.objects.filter(
            Q(**{f"{EMAIL_FIELD}__in": emails}) | Q(**{f"{PHONE_FIELD}__in": phones})
        )

        # generate and send tokens

        url_tokens = tokenizer.bulk_generate_tokenized_link(
            self.context.get("users"),
            path=self.context.get("path"),
            domain=self.context.get("domain"),
            protocol=self.context.get("protocol"),
            port=self.context.get("port"),
            channel=channel,
            template=self.context.get("template"),
            email_subject=self.context.get("email_subject"),
            fail_silently=self.context.get("fail_silently"),
        )

        for url_token in url_tokens:
            to = url_token.email if channel == Channel.EMAIL else url_token.phone
            log = url_token.log.pk if url_token.log else None
            if url_token.exception:
                validated_data.setdefault("errors", {})[to] = log
            elif url_token.precondition_failed:
                validated_data.setdefault("precondition_failed", {})[to] = log
            else:
                validated_data.setdefault("sent", {})[to] = log

        return validated_data


class CheckTokenSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    user_data = serializers.JSONField(required=False, default=dict)
    callbacks_kwargs = serializers.JSONField(required=False, write_only=True)
    callbacks_returns = serializers.JSONField(read_only=True)
    user = serializers.PrimaryKeyRelatedField(read_only=True)
    log = serializers.PrimaryKeyRelatedField(read_only=True)

    def create(self, validated_data):
        view = self.context["view"]

        token_type_url_kwarg = getattr(view, "token_type_url_kwarg", "type")
        assert token_type_url_kwarg in view.kwargs, _(
            "Expected view %s to be called with a URL keyword argument "
            "named 'type'. Fix your URL conf, or set the `.token_type_url_kwarg` "
            "attribute on the view correctly." % view.__class__.__name__
        )

        tokenizer = URLTokenizer(view.kwargs[token_type_url_kwarg])
        fail_silently = self.context.get("fail_silently")

        # check token

        uidb64, token = validated_data["uidb64"], validated_data["token"]
        user_data = validated_data["user_data"]
        user, log = tokenizer.check_token(
            uidb64, token, user_data=user_data, fail_silently=fail_silently
        )
        if user is None:
            raise AuthenticationFailed(_("The token is invalid or has expired."))

        # run callbacks

        callback_kwargs = validated_data.get("callbacks_kwargs", {})

        try:
            validated_data["callbacks_returns"] = tokenizer.run_callbacks(
                user, callback_kwargs=callback_kwargs, fail_silently=fail_silently
            )
        except URLTokenizerError as e:
            raise serializers.ValidationError(e)

        validated_data["user"] = user
        validated_data["log"] = log

        return validated_data


class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = "__all__"
