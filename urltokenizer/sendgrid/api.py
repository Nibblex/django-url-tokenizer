import base64
import json
import mimetypes
from os import getenv
from typing import Any

try:
    from sendgrid import SendGridAPIClient

    HAS_SENDGRID = True
except ImportError:
    HAS_SENDGRID = False


class SendgridAPI:
    def __init__(
        self,
        api_key: str,
        sender_name: str,
        sender_email: str,
    ):
        self.api_key = api_key
        self.sender_name = sender_name
        self.sender_email = sender_email
        self._client = self._create_client()

    def _create_client(self):
        if self.api_key and HAS_SENDGRID:
            return SendGridAPIClient(self.api_key)

        return None

    @property
    def client(self):
        return self._client

    @staticmethod
    def _validate_personalizations(personalizations: list):
        # Remove duplicates
        personalizations = list({json.dumps(p) for p in personalizations})
        personalizations = [json.loads(p) for p in personalizations]

        return personalizations

    def sg_send_mail(
        self,
        personalizations: list[dict[str, Any]],
        template_id: str,
        files: list | None = None,
        fail_silently: bool = False,
    ) -> int:
        personalizations = self._validate_personalizations(personalizations)

        # If no personalizations, return default response
        if not personalizations:
            return 0

        # Message payload
        message = {
            "personalizations": personalizations,
            "from": {
                "email": self.sender_email,
                "name": self.sender_name,
            },
            "template_id": template_id,
        }

        # Attachments
        attachments = []
        for file in files or []:
            try:
                data = file.read()
                encoded = base64.b64encode(data).decode()
            except (AttributeError, TypeError) as e:
                if fail_silently:
                    return 0

                raise e

            attachment = {
                "content": str(encoded),
                "type": mimetypes.guess_type(file.name)[0] or "application/octet-stream",
                "filename": str(file.name),
            }

            attachments.append(attachment)

        if attachments:
            message["attachments"] = attachments

        # Send
        try:
            response = self.client.send(message)
        except Exception as e:
            if fail_silently:
                return 0

            raise e

        if response.status_code == 202:
            return sum([len(p["to"]) for p in personalizations])

        return 0


sendgrid_api = SendgridAPI(
    api_key=getenv("SENDGRID_API_KEY", ""),
    sender_name=getenv("SENDGRID_SENDER_NAME", ""),
    sender_email=getenv("SENDGRID_SENDER_EMAIL", ""),
)
