import pytest

import urltokenizer

from .models import BaseProfile


def test_version_numbers():
    assert isinstance(urltokenizer.__version__, str)
    assert isinstance(urltokenizer.VERSION, tuple)
    assert all(isinstance(number, int) for number in urltokenizer.VERSION)
