import re

from django import forms
from django.db.models import Q
from django.conf import settings

from core.models import BaseUserProfile, OTPVerification


class LoginForm(forms.Form):
    """
    Login form view for validating user login. Throw validation
    as handled below
    """

    email = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super(LoginForm, self).clean()

        email = cleaned_data.get("email")
        password = cleaned_data.get("password")

        if not (email or password):
            msg = "Email and password are required"
            self._errors["password"] = self.error_class(["Password is required"])
            self._errors["email"] = self.error_class(["Email is required."])
            return self.cleaned_data

        if not email:
            msg = "Email is required"
            self._errors["email"] = self.error_class([msg])
            return self.cleaned_data

        user = BaseUserProfile.objects.filter(email__iexact=email)

        if not user.exists():
            msg = "Email or password is incorrect."
            self._errors["password"] = self.error_class([msg])
            return self.cleaned_data
        return self.cleaned_data


class OTPForm(forms.ModelForm):
    """
    Verify otp for a given user
    """
    class Meta:
        model = OTPVerification
        fields = ('otp',)

    def clean(self):
        cleaned_data = super(OTPForm, self).clean()
        otp = cleaned_data.get("otp")

        if not otp:
            msg = "Please enter otp"
            self._errors["otp"] = self.error_class([msg])
            return self.cleaned_data


class FPEmailForm(forms.Form):
    """
    Verify otp for a given user
    """
    email = forms.CharField()
    fields = ('email',)

    def clean(self):
        cleaned_data = super(FPEmailForm, self).clean()
        email = cleaned_data.get("email")

        if not email:
            msg = "Please enter email"
            self._errors["email"] = self.error_class([msg])
            return self.cleaned_data


class ChangePasswordForm(forms.ModelForm):
    """
    Verify otp for a given user
    """
    password = forms.CharField(
        widget=forms.PasswordInput(),
        label="password",
        max_length=50,
        error_messages={"required": "Please enter your password."},
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(),
        label="confirm_password",
        max_length=50,
        error_messages={"required": "Please enter confirm password."},
    )

    class Meta:
        model = BaseUserProfile
        fields = ('confirm_password', 'password',)

    def clean(self):
        cleaned_data = super(ChangePasswordForm, self).clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if not password or not confirm_password:
            msg = "Please add password and confirm password"
            self._errors["password"] = self.error_class([msg])

        if password != confirm_password:
            msg = "Both passwords do not match"
            self._errors["password"] = self.error_class([msg])


class SignUpForm(forms.ModelForm):
    """
    SignUpForm for user sign up, it will handle validation as given below
    """

    password = forms.CharField(
        widget=forms.PasswordInput(),
        label="password",
        max_length=50,
        error_messages={"required": "Please enter your password."},
    )
    email = forms.CharField(
        label="email", error_messages={"required": "Please enter your email."}
    )
    first_name = forms.CharField(
        label="first_name",
        error_messages={"required": "Please enter your first name."}
    )
    last_name = forms.CharField(
        label="last_name",
        error_messages={"required": "Please enter your last name."}
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(),
        label="confirm_password",
        max_length=50,
        error_messages={"required": "Please enter confirm password."},
    )
    phone_no = forms.CharField(
        label="phone_no",
        max_length=13,
        error_messages={"required": "Please enter your phone no."},
    )

    class Meta:
        model = BaseUserProfile
        fields = ("password", "email", "first_name", "last_name",
                  "confirm_password", "phone_no")

    def save(self):
        base_user = super(SignUpForm, self).save(commit=False)
        base_user.set_password(self.cleaned_data["password"])
        base_user.username = self.cleaned_data["email"]
        base_user.email = self.cleaned_data["email"]
        base_user.first_name = self.cleaned_data["first_name"]
        base_user.last_name = self.cleaned_data["last_name"]
        base_user.phone_no = self.cleaned_data["phone_no"]
        base_user.is_active = True
        base_user.save()
        return base_user

    def clean(self):
        cleaned_data = super(SignUpForm, self).clean()
        email = cleaned_data.get("email")
        confirm_password = cleaned_data.get("confirm_password")
        phone_no = cleaned_data.get("phone_no")
        password = cleaned_data.get("password")
        user = BaseUserProfile.objects.filter(
            Q(email__iexact=email) | Q(phone_no__iexact=phone_no))

        if user:
            msg = "User with the same email or phone no already exists!"
            self._errors["email"] = self.error_class([msg])
            return self.cleaned_data

        if not password or not confirm_password:
            msg = "Please add password and confirm password"
            self._errors["password"] = self.error_class([msg])

        if password != confirm_password:
            msg = "Both passwords do not match"
            self._errors["password"] = self.error_class([msg])
