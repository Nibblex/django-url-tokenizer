from enum import Enum

from .tokenizer import Tokenizer


class URLTokenizerMixin:
    @property
    def _uidb64(self) -> str:
        return Tokenizer.encode(getattr(self, self.ENCODING_FIELD, "pk"))

    def generate_tokenized_link(
        self, token_type: str | Enum, domain: str = None, send_email: bool = False
    ) -> tuple[str, str, str, bool]:
        tokenizer = Tokenizer(token_type)
        return tokenizer.generate_tokenized_link(
            self, domain=domain, send_email=send_email
        )

    def check_token(self, token_type: str | Enum, token: str, **kwargs) -> bool:
        tokenizer = Tokenizer(token_type)
        return tokenizer.check_token(self._uidb64, token, **kwargs) is not None
