import binascii
from os import urandom

from django_authx.settings import authx_settings


def generate_token(size=None) -> str:
    return binascii.hexlify(
        urandom(int(size or authx_settings.TOKEN_CHARACTER_LENGTH / 2))
    ).decode()
