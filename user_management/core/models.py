from django.db import models
from django.conf import settings

from django.contrib.auth.models import AbstractUser

# Create your models here.


class BaseUserProfile(AbstractUser):
    """
    Model class for base user.
    """
    address = models.CharField(max_length=255, blank=True, null=True)
    phone_no = models.CharField(max_length=10, blank=True, null=True)
    middle_name = models.CharField(max_length=255, blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Base User Profile"
        verbose_name_plural = "Base User Profiles"

    @property
    def full_name(self):
        if self.last_name and self.first_name:
            return "%s %s" % (self.first_name, self.last_name)
        elif self.first_name:
            return "%s " % (self.first_name)
        else:
            return "%s " % (self.email)

    def __str__(self):
        return f"{self.email}, is_active {self.is_active}"


class OTPVerification(models.Model):
    otp = models.CharField(max_length=5)
    created_on = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(BaseUserProfile, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"

    def __str__(self):
        return f"{self.user.email}, is_active {self.otp}, id: {self.id}"


class VerificationLink(models.Model):
    user = models.ForeignKey(BaseUserProfile, blank=False, null=False,
                             on_delete=models.CASCADE)
    hash_key = models.TextField(blank=False, null=False)
    created_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email}"


class ForgotPasswordLink(models.Model):
    user = models.ForeignKey(BaseUserProfile, blank=False, null=False,
                             on_delete=models.CASCADE)
    hash_key = models.TextField(blank=False, null=False)
    created_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email}"
