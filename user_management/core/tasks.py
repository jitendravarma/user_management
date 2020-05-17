from celery import Celery, task

from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from .models import BaseUserProfile, ForgotPasswordLink


celery = Celery('tasks', backend='redis', broker=settings.BROKER_URL)


def send_mail(subject, body, to_email):
    email_body = f"""
        <html>
            <body>
                {body}
            </body>
        </html>
    """
    email = EmailMultiAlternatives(
        subject, "", settings.EMAIL_HOST_USER, [to_email]
    )
    email.attach_alternative(email_body, "text/html")
    email.send()


# for sending mail for verification
@task(exchange="default", routing_key="default")
def send_verification_mail(data):
    subject = f"Please verify your account with App. Inc"
    body = f"""
    <p>
        Hello {data["full_name"]},
        <br>
        <p>Thank you, {data['full_name']} for registering with App. Inc</p>
        <p><a href="{settings.SERVER_URL}/verify-email/{data["hash_key"]}">Verify email</a></p>
        <br>
        Thanks,<br>
        Team App. Inc<br>
    </p>
    """
    send_mail(subject, body, data['to_email'])


# for sending mail for forgot password
@task(exchange="default", routing_key="default")
def send_forgot_password_mail(data):
    subject = f"Link to change password"
    body = f"""
    <p>
        Hello {data["full_name"]},
        <br>
        <p>Hi, {data['full_name']} here is your link to change your password</p>
        <p><a href="{settings.SERVER_URL}/forgot-password/{data["hash_key"]}">Verify email</a></p>
        <br>
        Thanks,<br>
        Team App. Inc<br>
    </p>
    """
    send_mail(subject, body, data['to_email'])


@task(exchange="default", routing_key="default")
def create_forgot_password_link(email):
    if BaseUserProfile.objects.filter(email=email).exists():
        user = BaseUserProfile.objects.filter(email=email).first()
        ForgotPasswordLink.objects.filter(user=user).delete()
        ForgotPasswordLink.objects.create(user=user)


@task(exchange="default", routing_key="default")
def send_otp_sms(message, phone_no):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages \
        .create(
            body=message, from_=settings.SMS_FROM,
            to=f"{settings.COUNTRY_CODE}{phone_no}"
        )
