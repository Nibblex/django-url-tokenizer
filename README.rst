django-url-tokenizer
====================

A Django app that generates time-limited, signed tokenized URLs and delivers them to users via email or SMS. It supports multiple token types, configurable callbacks, SendGrid integration, optional DRF serializers, and detailed logging.

.. contents:: Table of Contents
   :depth: 3
   :local:

----

Installation
------------

Install the core package::

    pip install django-url-tokenizer

Optional extras::

    # DRF serializer support
    pip install "django-url-tokenizer[serializers]"

    # SendGrid email backend
    pip install "django-url-tokenizer[sendgrid]"

    # SMS support (Twilio via django-sms)
    pip install "django-url-tokenizer[sms]"

Add ``urltokenizer`` to ``INSTALLED_APPS`` and run migrations::

    INSTALLED_APPS = [
        ...
        "urltokenizer",
    ]

.. code-block:: bash

    python manage.py migrate

----

Quick Start
-----------

1. Add ``URL_TOKENIZER_SETTINGS`` to your Django settings (see `Configuration`_ for all options).
2. Generate a tokenized link for a user and send it::

    from urltokenizer.tokenizer import URLTokenizer

    tokenizer = URLTokenizer("password_reset")
    url_token = tokenizer.generate_tokenized_link(user)
    print(url_token.link)
    # http://example.com:80/password-reset?uid=MTM&key=bcdef1-abcdef1234567890

3. Verify the token when the user clicks the link::

    user, log = tokenizer.check_token(uidb64, key)
    if user:
        # token is valid — proceed with the action

----

Configuration
-------------

All configuration lives under the ``URL_TOKENIZER_SETTINGS`` dictionary in your Django settings file.

.. code-block:: python

    URL_TOKENIZER_SETTINGS = {
        # ── Global defaults (can be overridden per token type in TOKEN_CONFIG) ──

        # Field used to encode the user identifier in the URL (default: "pk")
        "ENCODING_FIELD": "pk",

        # User attributes whose changes invalidate existing tokens (default: [])
        "ATTRIBUTES": ["password", "email"],

        # Token lifetime in seconds (default: 60)
        "TIMEOUT": 3600,

        # URL components used when building the tokenized link
        "PATH": "verify",           # URL path segment (default: "")
        "DOMAIN": "example.com",    # (default: "localhost")
        "PROTOCOL": "https",        # (default: "http")
        "PORT": "443",              # (default: "80")

        # Whether to deliver the link automatically after generation (default: False)
        "SEND_ENABLED": True,

        # Default delivery channel: "email" or "sms" (default: None)
        "CHANNEL": "email",

        # ── Email ──
        "EMAIL_FIELD": "email",                                     # (default: "email")
        "NAME_FIELD": "first_name",                                 # (default: "name")
        "EMAIL_SUBJECT": "Your verification link",                  # (default: package name)

        # ── SendGrid ──
        "SENDER_NAME": "My App",    # Display name for the FROM address (default: None)

        # Sendgrid dynamic template ID (default: None)
        "TEMPLATE_ID": "d-0123456789abcdef",

        # Plain-text/Jinja2 template string used when TEMPLATE_ID is not set (default: "")
        "PLAIN_CONTENT": "Hello {{name}}, click here: {{link}}",

        # Extra context passed to the template (default: {})
        "TEMPLATE_DATA": {"app_name": "My App"},

        # ── SMS ──
        "PHONE_FIELD": "phone",     # (default: "phone")

        # ── Logging ──
        # Persist each generation / check attempt to the Log model (default: False)
        "LOGGING_ENABLED": True,

        # ── Token check ──
        # Invalidate a token after first use by checking the Log table (default: False)
        "CHECK_LOGS": False,

        # Dotted path to a DRF serializer used to update the user on check (default: None)
        "USER_SERIALIZER": "myapp.serializers.UserSerializer",

        # Callbacks executed after a successful check (default: [])
        "CALLBACKS": [],

        # ── Error handling ──
        "FAIL_SILENTLY_ON_GENERATE": False,      # (default: False)
        "FAIL_SILENTLY_ON_BULK_GENERATE": False, # (default: False)
        "FAIL_SILENTLY_ON_CHECK": False,         # (default: False)
        "FAIL_SILENTLY_ON_CALLBACKS": False,     # (default: False)

        # ── Preconditions ──
        # Predicates evaluated before sending; sending is skipped when any returns False.
        "SEND_PRECONDITIONS": {
            "is_active": lambda user: user.is_active,
        },
        # Predicates evaluated before accepting a token check.
        "CHECK_PRECONDITIONS": {
            "is_active": lambda user: user.is_active,
        },
        # Shorthand that populates both SEND_PRECONDITIONS and CHECK_PRECONDITIONS.
        "PRECONDITIONS": {},

        # Whether to raise an error when an unknown token_type is passed (default: True)
        "VALIDATE_TOKEN_TYPE": True,

        # ── Per-type configuration ──
        "TOKEN_CONFIG": {
            "default": { ... },
            "password_reset": { ... },
            "email_verification": { ... },
        },
    }

TOKEN_CONFIG
~~~~~~~~~~~~

``TOKEN_CONFIG`` maps token-type names to individual configuration dictionaries. Each
dictionary accepts the **lowercase** equivalents of every top-level key above (they
override the global defaults for that token type only).

Reserved name: ``"default"`` — used when no token type is specified and as the
fallback when ``VALIDATE_TOKEN_TYPE`` is ``False``.

Full reference of per-type keys (all optional):

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Key
     - Default
     - Description
   * - ``encoding_field``
     - ``"pk"``
     - User model field whose value is base64-encoded into ``uidb64``.
   * - ``attributes``
     - ``[]``
     - List of user field names included in the token hash. Changing any of these fields invalidates existing tokens.
   * - ``timeout``
     - ``60``
     - Token lifetime in **seconds**. Set to ``0`` or ``None`` to disable expiry.
   * - ``extra_token_types``
     - ``[]``
     - List of additional token types whose tokens are appended to the URL as ``key2``, ``key3``, …
   * - ``path``
     - ``""``
     - URL path segment (leading/trailing slashes are stripped automatically).
   * - ``domain``
     - ``"localhost"``
     - Hostname or IP of the target server.
   * - ``protocol``
     - ``"http"``
     - URL scheme (``"http"`` or ``"https"``).
   * - ``port``
     - ``"80"``
     - Port number included in the URL.
   * - ``send_enabled``
     - ``False``
     - When ``True``, the link is delivered automatically after generation.
   * - ``channel``
     - ``None``
     - Delivery channel: ``"email"`` or ``"sms"``.
   * - ``send_preconditions``
     - ``{}``
     - Dict of ``{name: callable}`` predicates. Generation is aborted (no exception) when any predicate returns ``False``.
   * - ``template_id``
     - ``None``
     - SendGrid dynamic template ID. Takes precedence over ``plain_content``.
   * - ``plain_content``
     - ``""``
     - Jinja2 template string rendered when ``template_id`` is not set.
   * - ``template_data``
     - ``{}``
     - Extra context injected into the template. Values may be callables that receive the ``URLToken``.
   * - ``email_field``
     - ``"email"``
     - User model field containing the recipient e-mail address.
   * - ``name_field``
     - ``"name"``
     - User model field used as the recipient display name.
   * - ``email_subject``
     - ``"link generated with django-url-tokenizer"``
     - Subject line for plain-email delivery.
   * - ``sender_name``
     - ``None``
     - Display name for the FROM address when using SendGrid.
   * - ``phone_field``
     - ``"phone"``
     - User model field containing the recipient phone number.
   * - ``logging_enabled``
     - ``False``
     - Persist generation and check events to the ``Log`` model.
   * - ``check_preconditions``
     - ``{}``
     - Dict of ``{name: callable}`` predicates evaluated during ``check_token``.
   * - ``check_logs``
     - ``False``
     - When ``True``, a token can only be used **once** (requires ``logging_enabled``).
   * - ``callbacks``
     - ``[]``
     - List of callback descriptors executed after a successful ``check_token``. See `Callbacks`_.
   * - ``fail_silently_on_generate``
     - ``False``
     - Suppress exceptions raised during ``generate_tokenized_link``.
   * - ``fail_silently_on_bulk_generate``
     - ``False``
     - Suppress exceptions raised during ``bulk_generate_tokenized_link``.
   * - ``fail_silently_on_check``
     - ``False``
     - Suppress exceptions raised during ``check_token``.
   * - ``fail_silently_on_callbacks``
     - ``False``
     - Suppress exceptions raised inside callbacks.

Example with multiple token types::

    URL_TOKENIZER_SETTINGS = {
        "DOMAIN": "example.com",
        "PROTOCOL": "https",
        "PORT": "443",
        "TIMEOUT": 3600,
        "SEND_ENABLED": True,
        "CHANNEL": "email",
        "EMAIL_SUBJECT": "Your link",
        "LOGGING_ENABLED": True,

        "TOKEN_CONFIG": {
            "default": {
                "path": "verify",
                "timeout": 300,
            },
            "password_reset": {
                "path": "auth/reset-password",
                "timeout": 900,
                "attributes": ["password"],
                "check_logs": True,
                "callbacks": [
                    {"builtin": "serialize_user", "return_value": True},
                ],
            },
            "email_verification": {
                "path": "auth/verify-email",
                "timeout": 86400,
                "attributes": ["email"],
                "send_preconditions": {
                    "not_verified": lambda user: not user.email_verified,
                },
                "check_preconditions": {
                    "not_verified": lambda user: not user.email_verified,
                },
                "callbacks": [
                    {"method": "verify_email"},
                ],
            },
        },
    }

----

URLToken
--------

``generate_tokenized_link`` returns a ``URLToken`` dataclass instance with the
following attributes:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Attribute
     - Description
   * - ``user``
     - The Django user object.
   * - ``type``
     - The token type string (or ``None`` for the default type).
   * - ``created_at``
     - ``datetime`` when the token was created.
   * - ``expires_at``
     - ``datetime`` when the token expires.
   * - ``uidb64``
     - URL-safe base64-encoded user identifier.
   * - ``token``
     - The signed token string (``<ts_b36>-<hash>``).
   * - ``link``
     - The full tokenized URL.
   * - ``hash``
     - SHA-256 hash of ``uidb64 + token`` stored in the ``Log`` entry.
   * - ``email``
     - Recipient e-mail address (read from the user).
   * - ``name``
     - Recipient display name (read from the user).
   * - ``phone``
     - Recipient phone number (read from the user).
   * - ``channel``
     - Delivery channel used (``Channel.EMAIL`` or ``Channel.SMS``).
   * - ``precondition_failed``
     - Name of the first failed send precondition (or ``None``).
   * - ``sent``
     - ``True`` if the link was delivered successfully.
   * - ``exception``
     - ``URLTokenizerError`` instance if an error occurred (or ``None``).
   * - ``log``
     - Associated ``Log`` model instance (or ``None`` if logging is disabled).
   * - ``extra_tokens``
     - Dict of ``{token_type: token}`` for any ``extra_token_types``.

----

Usage
-----

URLTokenizer class
~~~~~~~~~~~~~~~~~~

The ``URLTokenizer`` class is the primary entry point::

    from urltokenizer.tokenizer import URLTokenizer

    tokenizer = URLTokenizer("password_reset")

    # Generate a link (does not send)
    url_token = tokenizer.generate_tokenized_link(user)
    print(url_token.link)
    # https://example.com:443/auth/reset-password?uid=MTM&key=abc123-def456

    # Generate and send via email (send_enabled=True in config)
    url_token = tokenizer.generate_tokenized_link(user, channel="email")
    print(url_token.sent)   # True

    # Override URL components at call time
    url_token = tokenizer.generate_tokenized_link(
        user,
        path="custom/path",
        domain="other.example.com",
        protocol="https",
        port="443",
        channel="email",
        email_subject="Custom subject",
    )

    # Dynamic path based on the user object
    url_token = tokenizer.generate_tokenized_link(
        user,
        path=lambda u: f"users/{u.pk}/verify",
    )

    # Verify a token received from a URL query parameter
    user, log = tokenizer.check_token(uidb64, key)
    if user:
        print("Token is valid for", user)

    # Run callbacks separately (or after a successful check)
    results = tokenizer.run_callbacks(user)

Bulk generation
~~~~~~~~~~~~~~~

Generate and (optionally) send links to many users in parallel::

    from urltokenizer.tokenizer import URLTokenizer

    tokenizer = URLTokenizer("email_verification")
    users = User.objects.filter(email_verified=False)
    url_tokens = tokenizer.bulk_generate_tokenized_link(users)

    for url_token in url_tokens:
        if url_token.sent:
            print(f"Sent to {url_token.email}")
        elif url_token.precondition_failed:
            print(f"Skipped {url_token.email}: precondition '{url_token.precondition_failed}' failed")
        elif url_token.exception:
            print(f"Error for {url_token.email}: {url_token.exception}")

Using the default tokenizer
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A module-level ``default_tokenizer`` instance (using the ``"default"`` token type)
is available for convenience::

    from urltokenizer.tokenizer import default_tokenizer

    url_token = default_tokenizer.generate_tokenized_link(user)

URLTokenizerMixin
~~~~~~~~~~~~~~~~~

Add ``URLTokenizerMixin`` to your custom user model to call the tokenizer directly
on a user instance::

    # models.py
    from django.contrib.auth.models import AbstractUser
    from urltokenizer.mixins import URLTokenizerMixin

    class User(URLTokenizerMixin, AbstractUser):
        phone = models.CharField(max_length=20, blank=True)
        email_verified = models.BooleanField(default=False)

        def verify_email(self):
            self.email_verified = True
            self.save(update_fields=["email_verified"])

Then in your views or services::

    # Generate and send a link
    url_token = user.generate_tokenized_link(token_type="email_verification")

    # Check a token and run configured callbacks
    valid, log, callbacks_returns = user.check_token(
        token_type="email_verification",
        token=key,
    )

URLTokenizerManager / QuerySet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``URLTokenizerManager`` on your user model to bulk-generate links directly
from a queryset::

    # models.py
    from urltokenizer.managers import URLTokenizerManager

    class User(AbstractUser):
        objects = URLTokenizerManager()

    # Bulk generate for a filtered queryset
    url_tokens = User.objects.filter(
        email_verified=False
    ).bulk_generate_tokenized_link(
        token_type="email_verification",
        channel="email",
    )

DRF Serializers (optional extra)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Three ready-made DRF serializers are provided. Wire them up in your URL conf and
views as context providers.

``SendTokenSerializer``
    Accepts ``channel`` + ``email`` (or ``phone``), looks up the user, and
    delivers a tokenized link::

        # serializer context keys:
        # view (required), path, domain, protocol, port,
        # channel, template, email_subject, fail_silently

        POST /api/token/<type>/send/
        {
            "channel": "email",
            "email": "user@example.com"
        }

``BulkSendTokenSerializer``
    Accepts ``channel`` + ``emails`` (or ``phones``) and bulk-delivers links::

        POST /api/token/<type>/bulk-send/
        {
            "channel": "email",
            "emails": ["alice@example.com", "bob@example.com"]
        }

``CheckTokenSerializer``
    Verifies ``uidb64`` + ``token``, optionally updates the user, and runs
    callbacks::

        POST /api/token/<type>/check/
        {
            "uidb64": "MTM",
            "token": "abc123-def456",
            "callbacks_kwargs": [{"data": {"email_verified": true}}]
        }

----

Channels
--------

Email
~~~~~

Plain Django ``send_mail`` is used by default. Configure the standard Django email
settings (``EMAIL_BACKEND``, ``EMAIL_HOST``, ``DEFAULT_FROM_EMAIL``, etc.)::

    URL_TOKENIZER_SETTINGS = {
        "CHANNEL": "email",
        "EMAIL_FIELD": "email",
        "NAME_FIELD": "first_name",
        "EMAIL_SUBJECT": "Your verification link",
        "SEND_ENABLED": True,
        ...
    }

SendGrid
^^^^^^^^

Install the SendGrid extra and set ``SENDGRID_API_KEY`` in your environment::

    pip install "django-url-tokenizer[sendgrid]"

Then configure a SendGrid dynamic template::

    URL_TOKENIZER_SETTINGS = {
        "SENDER_NAME": "My App",
        "TOKEN_CONFIG": {
            "password_reset": {
                "channel": "email",
                "send_enabled": True,
                "template_id": "d-0123456789abcdef",
                "template_data": {
                    "app_name": "My App",
                    "subject": "Reset your password",
                },
            },
        },
    }

SMS
~~~

Install the SMS extra (Twilio backend)::

    pip install "django-url-tokenizer[sms]"

Configure ``django-sms`` as described in its documentation, then::

    URL_TOKENIZER_SETTINGS = {
        "PHONE_FIELD": "phone",
        "TOKEN_CONFIG": {
            "login": {
                "channel": "sms",
                "send_enabled": True,
                "plain_content": "Your login link: {{link}}",
            },
        },
    }

----

Templates
---------

Plain content (Jinja2)
~~~~~~~~~~~~~~~~~~~~~~

Use ``plain_content`` with `Jinja2 <https://jinja.palletsprojects.com/>`_ syntax.
Available variables are resolved from user attributes and ``template_data``::

    URL_TOKENIZER_SETTINGS = {
        "PLAIN_CONTENT": (
            "Hi {{first_name}},\n\n"
            "Click the link below to verify your email:\n{{link}}\n\n"
            "The link expires in {{timeout_minutes}} minutes."
        ),
        # TIMEOUT is in seconds; convert to minutes for display
        "TEMPLATE_DATA": {
            "timeout_minutes": lambda url_token: int(
                (url_token.expires_at - url_token.created_at).total_seconds() // 60
            ),
        },
    }

The template context is built from:

1. User attributes whose names appear as ``{{variable}}`` placeholders.
2. Keys in ``template_data`` (values that are callables receive the ``URLToken``).

SendGrid dynamic templates
~~~~~~~~~~~~~~~~~~~~~~~~~~

When ``template_id`` is set, SendGrid dynamic template data is built the same way
and sent via the Personalizations API::

    "TEMPLATE_DATA": {
        "action_url": lambda url_token: url_token.link,
        "username": lambda url_token: url_token.user.username,
    },

----

Callbacks
---------

Callbacks are executed after a successful ``check_token`` call. Each callback is
described by a dict with **exactly one** of the following resolver keys, plus
optional control keys.

Resolver keys
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Key
     - Description
   * - ``method``
     - Name of a method on the user model instance. Called as ``user.<method>(**kwargs)``.
   * - ``path``
     - Dotted Python import path to a callable. Called as ``func(**kwargs)``.
   * - ``lambda``
     - A Python ``lambda`` that receives the user as its first positional argument, followed by ``**kwargs``.
   * - ``builtin``
     - Name of a built-in callback (see `Built-in Callbacks`_).

Control keys
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Key
     - Description
   * - ``return_value``
     - When ``True``, the return value of the callback is collected and included in ``run_callbacks`` results (default: ``False``).
   * - ``defaults``
     - Dict of default keyword arguments merged with any matching ``callback_kwargs`` supplied at runtime.

Examples::

    "CALLBACKS": [
        # Call a method on the user model
        {"method": "activate"},

        # Call a function by import path
        {"path": "myapp.tasks.send_welcome_email"},

        # Call a lambda (user is passed automatically)
        {"lambda": lambda user, **kwargs: user.set_unusable_password()},

        # Built-in: serialize and return the user
        {"builtin": "serialize_user", "return_value": True},

        # Provide default kwargs merged with runtime kwargs
        {
            "method": "set_password",
            "defaults": {"raw_password": "temporary123"},
            "return_value": False,
        },
    ]

Passing kwargs at runtime::

    results = tokenizer.run_callbacks(
        user,
        callback_kwargs=[
            {"raw_password": request.data["new_password"]},
        ],
    )

Via ``URLTokenizerMixin``::

    valid, log, results = user.check_token(
        token_type="password_reset",
        token=key,
        callback_kwargs=[{"raw_password": new_password}],
    )

----

Built-in Callbacks
------------------

``serialize_user``
~~~~~~~~~~~~~~~~~~

Serializes the user object using the serializer class configured under
``USER_SERIALIZER`` in ``URL_TOKENIZER_SETTINGS``. Returns a dict of the user's
serialized data, or ``None`` when no serializer is configured::

    URL_TOKENIZER_SETTINGS = {
        "USER_SERIALIZER": "myapp.serializers.UserSerializer",
        "TOKEN_CONFIG": {
            "login": {
                "callbacks": [
                    {"builtin": "serialize_user", "return_value": True},
                ],
            },
        },
    }

    user, log = tokenizer.check_token(uidb64, key)
    results = tokenizer.run_callbacks(user)
    user_data = results["serialize_user"][0]

``patch_user``
~~~~~~~~~~~~~~

Partially updates the user using the configured ``USER_SERIALIZER``. Accepts a
``data`` keyword argument::

    URL_TOKENIZER_SETTINGS = {
        "USER_SERIALIZER": "myapp.serializers.UserSerializer",
        "TOKEN_CONFIG": {
            "email_verification": {
                "callbacks": [
                    {"builtin": "patch_user", "return_value": True},
                ],
            },
        },
    }

    results = tokenizer.run_callbacks(
        user,
        callback_kwargs=[{"data": {"email_verified": True}}],
    )

----

Logging
-------

Set ``logging_enabled`` (or ``LOGGING_ENABLED``) to ``True`` to persist every
generation and check attempt to the ``Log`` model.

``Log`` model fields:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Description
   * - ``created_at``
     - When the tokenized link was generated.
   * - ``checked_at``
     - When the token was successfully checked (``None`` until checked).
   * - ``expires_at``
     - When the token expires.
   * - ``token_type``
     - The token type string.
   * - ``uidb64``
     - Base64-encoded user identifier.
   * - ``hash``
     - SHA-256 of ``uidb64 + token`` (unique).
   * - ``name``
     - Recipient display name.
   * - ``email``
     - Recipient e-mail address.
   * - ``phone``
     - Recipient phone number.
   * - ``channel``
     - Delivery channel used.
   * - ``send_precondition_failed``
     - Name of the failed send precondition (if any).
   * - ``check_precondition_failed``
     - Name of the failed check precondition (if any).
   * - ``sent``
     - Whether the link was delivered successfully.
   * - ``errors``
     - String representation of any exception.
   * - ``user``
     - Foreign key to the user model.

``Log`` also exposes a ``checked`` boolean property and a ``_check()`` method used
internally to mark a log entry as consumed.

One-time tokens
~~~~~~~~~~~~~~~

Enable ``check_logs`` alongside ``logging_enabled`` to make tokens single-use.
Once the link has been clicked (i.e., ``log.checked_at`` is set), subsequent
attempts will fail::

    URL_TOKENIZER_SETTINGS = {
        "LOGGING_ENABLED": True,
        "TOKEN_CONFIG": {
            "password_reset": {
                "logging_enabled": True,
                "check_logs": True,
            },
        },
    }

----

Preconditions
-------------

Preconditions are plain callables (or dotted import paths to callables) that
receive the user object and return a boolean. When any precondition returns
``False``, the operation is silently aborted (``url_token.precondition_failed``
is set to the precondition name).

Send preconditions
~~~~~~~~~~~~~~~~~~

Evaluated before delivering a link. If one fails, the token is generated but not
sent::

    URL_TOKENIZER_SETTINGS = {
        "TOKEN_CONFIG": {
            "email_verification": {
                "send_preconditions": {
                    "not_verified": lambda user: not user.email_verified,
                    "is_active": "myapp.predicates.is_active_user",
                },
            },
        },
    }

Check preconditions
~~~~~~~~~~~~~~~~~~~

Evaluated during ``check_token``. If one fails, ``check_token`` returns
``(None, None)``::

    "check_preconditions": {
        "is_active": lambda user: user.is_active,
    },

Global preconditions
~~~~~~~~~~~~~~~~~~~~

The top-level ``PRECONDITIONS`` key populates **both** ``SEND_PRECONDITIONS``
and ``CHECK_PRECONDITIONS``. Per-type entries are merged on top::

    URL_TOKENIZER_SETTINGS = {
        "PRECONDITIONS": {
            "is_active": lambda user: user.is_active,
        },
    }

----

Error Handling
--------------

``URLTokenizerError`` is raised on invalid configurations or runtime errors. It
carries three attributes:

* ``message`` — human-readable description.
* ``code`` — machine-readable error code string.
* ``context`` — dict with extra information (e.g., the original exception).

Available error codes:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Code
     - Meaning
   * - ``invalid_token_type``
     - The requested token type is not defined in ``TOKEN_CONFIG``.
   * - ``invalid_method``
     - A ``method`` callback does not exist on the user or is not callable.
   * - ``no_email``
     - The user has no e-mail address and email delivery was requested.
   * - ``no_phone``
     - The user has no phone number and SMS delivery was requested.
   * - ``send_precondition_execution_error``
     - An exception occurred while evaluating a send precondition.
   * - ``check_precondition_execution_error``
     - An exception occurred while evaluating a check precondition.
   * - ``callback_configuration_error``
     - A callback dict is missing its resolver key.
   * - ``invalid_builtin_callback``
     - The ``builtin`` key references an unknown built-in callback name.
   * - ``callback_execution_error``
     - An exception occurred inside a callback.

fail_silently flags
~~~~~~~~~~~~~~~~~~~

Each operation has its own ``fail_silently`` flag (settable globally, per token
type, or at call time). When ``True``, exceptions are swallowed and the operation
returns a result with ``url_token.exception`` set::

    url_token = tokenizer.generate_tokenized_link(user, fail_silently=True)
    if url_token.exception:
        logger.warning("Token generation issue: %s", url_token.exception)

----

Full Configuration Example
---------------------------

.. code-block:: python

    # settings.py

    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    DEFAULT_FROM_EMAIL = "noreply@example.com"

    URL_TOKENIZER_SETTINGS = {
        "DOMAIN": "example.com",
        "PROTOCOL": "https",
        "PORT": "443",
        "SEND_ENABLED": True,
        "CHANNEL": "email",
        "LOGGING_ENABLED": True,
        "ATTRIBUTES": ["password"],
        "PRECONDITIONS": {
            "is_active": lambda user: user.is_active,
        },
        "TOKEN_CONFIG": {
            "default": {
                "path": "verify",
                "timeout": 300,
            },
            "password_reset": {
                "path": "auth/reset-password",
                "email_subject": "Reset your password",
                "timeout": 900,
                "attributes": ["password"],
                "check_logs": True,
                "callbacks": [
                    {
                        "method": "set_password",
                        "defaults": {},
                    },
                    {"builtin": "serialize_user", "return_value": True},
                ],
            },
            "email_verification": {
                "path": "auth/verify-email",
                "email_subject": "Verify your email address",
                "timeout": 86400,
                "attributes": ["email"],
                "send_preconditions": {
                    "not_verified": lambda user: not user.email_verified,
                },
                "check_preconditions": {
                    "not_verified": lambda user: not user.email_verified,
                },
                "callbacks": [
                    {"method": "verify_email"},
                ],
            },
            "magic_link": {
                "path": "auth/magic-login",
                "email_subject": "Your magic login link",
                "timeout": 600,
                "check_logs": True,
                "callbacks": [
                    {"builtin": "serialize_user", "return_value": True},
                ],
            },
        },
    }

----

License
-------

MIT

