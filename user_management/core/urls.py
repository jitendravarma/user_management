from django.conf.urls import url
from django.contrib.auth import logout

from .views import (
    LoginView, LogOutView, SignupView, OTPView, IndexView,
    VerifyLinkView, LinkExpireView, ForgotPasswordView,
    ForgotPasswordLinkView)


urlpatterns = [
    # for user authentication
    url(r'^login/$', LoginView.as_view(), name="login-view"),
    url(r'^signup/$', SignupView.as_view(), name="signup-view"),
    url(r'^logout/$', LogOutView.as_view(), name="logout-view"),
    # for dashboard view
    url(r'^home/$', IndexView.as_view(), name="index-view"),
    # to verify phone no
    url(r'^phone-verification/$', OTPView.as_view(),
        name="phone-verification-view"),
    # to verify emails
    url(r"verify-email/(?P<slug>[-\w\d]+)$",
        VerifyLinkView.as_view(), name="verify-email-view",),
    url(r'^link-expire/$', LinkExpireView.as_view(), name="link-expire-view"),
    url(r'^forgot-password/$', ForgotPasswordView.as_view(), name="forgot-password-view"),
    url(r'^forgot-password/(?P<slug>[-\w\d]+)$', ForgotPasswordLinkView.as_view(), name="forgot-password-link-view"),
]
