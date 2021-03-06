import string
import random

from django.conf import settings
from django.dispatch import receiver
from django.utils.encoding import force_bytes
from django.db.models.signals import post_save
from django.utils.http import urlsafe_base64_encode

from .tasks import (send_verification_mail, send_forgot_password_mail,
                    send_otp_sms)
from .models import (BaseUserProfile, OTPVerification, VerificationLink,
                     ForgotPasswordLink)


def get_otp_code(otp_size=5):
    return ''.join(random.choices(string.digits, k=otp_size))


def create_otp(user):
    otp_code = get_otp_code()
    OTPVerification.objects.filter(user=user).delete()
    OTPVerification.objects.create(user=user, otp=otp_code)
    return otp_code


def get_otp_message(otp):
    message = f"""Your one time password for App. Inc is {otp} 
    Please do not share this with anyone.
    Regards
    Team App. Inc
    """
    return message


def send_mail_verification(instance):
    hash_key = urlsafe_base64_encode(force_bytes(instance.email))
    data = {"full_name": instance.full_name,
            "to_email": instance.email, "hash_key": hash_key}
    VerificationLink.objects.filter(user=instance).delete()
    VerificationLink.objects.create(user=instance, hash_key=hash_key)
    send_verification_mail.delay(data)


def send_otp(instance):
    otp_code = create_otp(instance)
    message = get_otp_message(otp_code)
    send_otp_sms.delay(message, instance.phone_no)


@receiver(post_save, sender=BaseUserProfile)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        send_otp(instance)
        send_mail_verification(instance)


def get_mail_message(link):
    message = f"""Here is your link to change password: 
    {settings.SERVER_URL}/forgot-password/{link}
    Please dont share this with any one.
    Regards
    Team App. Inc
    """
    return message


def send_password_mail(instance):
    hash_key = urlsafe_base64_encode(force_bytes(instance.user.email))
    data = {"full_name": instance.user.full_name,
            "to_email": instance.user.email, "hash_key": hash_key}
    instance.hash_key = hash_key
    instance.save()
    send_forgot_password_mail.delay(data)
    message = get_mail_message(hash_key)
    send_otp_sms.delay(message, instance.user.phone_no)


@receiver(post_save, sender=ForgotPasswordLink)
def create_forgot_passwork_link(sender, instance, created, **kwargs):
    if created:
        send_password_mail(instance)
