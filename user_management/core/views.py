import json

from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login, logout
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect, HttpResponse
from django.views.generic import RedirectView, FormView, TemplateView

from .backends import EmailModelBackend
from .forms import LoginForm, SignUpForm, OTPForm, FPEmailForm
from .models import (BaseUserProfile, OTPVerification,
                     VerificationLink, ForgotPasswordLink)
from .tasks import send_forgot_password_mail


# Create your views here.

class IndexView(LoginRequiredMixin, TemplateView):
    """
    Home view for user after redirection
    """

    template_name = 'frontend/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(IndexView, self).get_context_data(**kwargs)
        context['dashboard_page'] = "active"
        user = self.request.user
        context['email_verified'] = user.email_verified
        return context


class LoginView(FormView):
    """
    This view handles authentication of the user, when they first time logs in
    redirects them to login page if not authenticated.
    """
    form_class = LoginForm
    template_name = 'frontend/login.html'

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        return context

    def post(self, request):
        form = LoginForm(request.POST)
        email = form.data['email']
        password = form.data['password']
        if form.is_valid():
            user_auth = EmailModelBackend()
            user = user_auth.validate_password(password=password, email=email)
            if user:
                otp_id = OTPVerification.objects.get(user=user).id
                return HttpResponseRedirect(
                    reverse('phone-verification-view') + f"?otp_id={otp_id}")
        context = {
            'form': form,
            "csrf_token": form.data['csrfmiddlewaretoken'], 'email': email
        }
        return render(
            request, context=context, template_name=self.template_name)


class LogOutView(RedirectView):
    """
    logout view
    """

    def get_redirect_url(self):
        url = reverse("login-view")
        logout(self.request)
        return url


class SignupView(FormView):
    """
    This view signs up new user and validates the form on the server side
    """

    form_class = SignUpForm
    template_name = 'frontend/sign-up.html'

    def post(self, request, *args, **kwargs):
        form = SignUpForm(request.POST)
        email = form.data['email']
        password = form.data['password']
        if form.is_valid():
            user = form.save()
            otp_id = OTPVerification.objects.get(user=user).id
            return HttpResponseRedirect(
                reverse('phone-verification-view') + f"?otp_id={otp_id}")
        context = {
            'form': form, "csrf_token": form.data['csrfmiddlewaretoken'],
            'email': email
        }
        return render(
            request, context=context, template_name=self.template_name)


class OTPView(FormView):
    """
    This view handles otp verification
    """
    form_class = OTPForm
    template_name = 'frontend/otp.html'

    def get_context_data(self, **kwargs):
        context = super(OTPView, self).get_context_data(**kwargs)
        otp_id = self.request.GET.get('otp_id')
        context["otp_id"] = otp_id
        get_object_or_404(OTPVerification, id=otp_id)
        return context

    def post(self, request, *args, **kwargs):
        form = OTPForm(request.POST)
        otp = form.data['otp']
        otp_id = form.data['otp_id']
        if not form.is_valid():
            context = {
                'form': form, "csrf_token": form.data['csrfmiddlewaretoken'],
                'otp_id': otp_id}
            return render(
                request, context=context, template_name=self.template_name)
        else:
            otp_verified = get_object_or_404(OTPVerification, id=otp_id)
            user_auth = EmailModelBackend()
            user = user_auth.authenticate(_id=otp_id, otp=otp)
            if user:
                login(self.request, user)
                if "next" in self.request.GET:
                    url = self.request.GET["next"]
                    response = HttpResponseRedirect(url)
                    return response
                else:
                    response = HttpResponseRedirect('/home')
                    return response
            else:
                messages.error(self.request, "Incorrect OTP entered")
                return HttpResponseRedirect(
                    reverse('phone-verification-view') + f"?otp_id={otp_id}")


class LinkExpireView(TemplateView):
    """
    This view is to redirect user after confirming email
    """

    template_name = 'frontend/link-expire.html'


class VerifyLinkView(TemplateView):

    template_name = "frontend/verification.html"

    def dispatch(self, request, *args, **kwargs):
        if not VerificationLink.objects.filter(hash_key=self.kwargs["slug"]).exists():
            return HttpResponseRedirect(reverse("link-expire-view"))
        return super(VerifyLinkView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(VerifyLinkView, self).get_context_data(**kwargs)
        slug = self.kwargs["slug"]
        context["link"] = get_object_or_404(VerificationLink, hash_key=slug)
        uid = force_text(urlsafe_base64_decode(self.kwargs["slug"]))
        email = force_text(urlsafe_base64_decode(slug))
        BaseUserProfile.objects.filter(email=user_id).update(
            is_active=True, email_verified=True)
        VerificationLink.objects.filter(hash_key=slug).delete()
        return context


class ForgotPasswordView(TemplateView):

    template_name = "frontend/verification.html"

    def dispatch(self, request, *args, **kwargs):
        if not VerificationLink.objects.filter(hash_key=self.kwargs["slug"]).exists():
            return HttpResponseRedirect(reverse("link-expire-view"))
        return super(ForgotPasswordView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ForgotPasswordView, self).get_context_data(**kwargs)
        slug = self.kwargs["slug"]
        get_object_or_404(ForgotPasswordLink, hash_key=slug)
        # ForgotPasswordLink.objects.filter(hash_key=slug).delete()
        return context


class ForgotPasswordMailView(FormView):
    """
    This view confirms email for forgot password
    """
    form_class = FPEmailForm
    template_name = 'frontend/send-fp-mail.html'

    def post(self, request, *args, **kwargs):
        form = FPEmailForm(request.POST)
        email = form.data['email']
        if not form.is_valid():
            context = {
                'form': form, "csrf_token": form.data['csrfmiddlewaretoken'], }
            return render(
                request, context=context, template_name=self.template_name)
        messages.error(self.request, "If your email exists in our database\
                       we will send your link to change your password")
        user = BaseUserProfile.objects.filter(email=email)
        return HttpResponseRedirect(reverse('forgot-password-view'))
