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
