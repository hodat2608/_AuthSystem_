from django.contrib.auth.tokens import default_token_generator
from templated_mail.mail import BaseEmailMessage

from accounts import utils
from django.conf import settings


class ActivationEmail(BaseEmailMessage):
    template_name = "static/activation.html"

    def get_context_data(self):
        # ActivationEmail can be deleted
        context = super().get_context_data()

        user = context.get("user")
        context["uid"] = utils.encode_uid(user.pk)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.ACTIVATION_URL.format(**context)
        return context
    
class ConfirmationEmail(BaseEmailMessage):
    template_name = "static/confirmation.html"


class PasswordResetEmail(BaseEmailMessage):
    template_name = "static/password_reset.html"

    def get_context_data(self):
        # PasswordResetEmail can be deleted
        context = super().get_context_data()

        user = context.get("user")
        context["uid"] = utils.encode_uid(user.pk)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.PASSWORD_RESET_CONFIRM_URL.format(**context)
        return context


class PasswordChangedConfirmationEmail(BaseEmailMessage):
    template_name = "static/password_changed_confirmation.html"


class UsernameChangedConfirmationEmail(BaseEmailMessage):
    template_name = "static/username_changed_confirmation.html"


class UsernameResetEmail(BaseEmailMessage):
    template_name = "static/username_reset.html"

    def get_context_data(self):
        context = super().get_context_data()

        user = context.get("user")
        context["uid"] = utils.encode_uid(user.pk)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.USERNAME_RESET_CONFIRM_URL.format(**context)
        return context
