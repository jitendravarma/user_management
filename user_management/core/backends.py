from django.contrib.auth.backends import ModelBackend

from .models import BaseUserProfile, OTPVerification
from .signals import send_otp


class EmailModelBackend(ModelBackend):
    """
    This is a ModelBackend that allows authentication with an email address.
    """

    def validate_password(self, email=None, password=None):
        users = BaseUserProfile.objects.filter(email__iexact=email)
        if users.exists():
            user = users.first()
            if user.check_password(password):
                send_otp(user)
                return user
        else:
            return None

    def authenticate(self, _id=None, otp=None):
        verified = OTPVerification.objects.filter(id=_id, otp=otp)
        if verified.exists():
            user = verified.first().user
            verified.delete()
            return user
        return None

    def get_user(self, username):
        try:
            return BaseUserProfile.objects.get(pk=username)
        except BaseUserProfile.DoesNotExist:
            return None
