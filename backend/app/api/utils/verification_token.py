#! for token generate in serilizer or else where require
import jwt
from datetime import datetime, timezone, timedelta
from django.conf import settings


def generate_verification_token(user_id):
    if not user_id:
        raise ValueError("user_id must be provided")
    payload = {
        'user_id': user_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    return token
