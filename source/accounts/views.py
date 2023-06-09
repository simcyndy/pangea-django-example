from django.contrib import messages
from django.contrib.auth import login, authenticate, REDIRECT_FIELD_NAME
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    LogoutView as BaseLogoutView, PasswordChangeView as BasePasswordChangeView,
    PasswordResetDoneView as BasePasswordResetDoneView, PasswordResetConfirmView as BasePasswordResetConfirmView,
)
from django.shortcuts import get_object_or_404, redirect
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme as is_safe_url
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View, FormView
from django.contrib import messages
import hashlib
# from django.conf.development import settings

from .utils import (
    send_activation_email, send_reset_password_email, send_forgotten_username_email, send_activation_change_email,
)
from .forms import (
    SignInViaUsernameForm, SignInViaEmailForm, SignInViaEmailOrUsernameForm, SignUpForm,
    RestorePasswordForm, RestorePasswordViaEmailOrUsernameForm, RemindUsernameForm,
    ResendActivationCodeForm, ResendActivationCodeViaEmailForm, ChangeProfileForm, ChangeEmailForm,
    DocumentForm
)
from .models import Activation, Document
from app.conf.development import settings
from django.shortcuts import redirect, render

from pangea.config import PangeaConfig
from pangea.services import Audit, FileIntel
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseBadRequest

config = PangeaConfig(domain=settings.PANGEA_DOMAIN)
audit = Audit(settings.PANGEA_AUDIT_TOKEN, config=config) #creating Secure Audit Log object

# Create the audit object within the class
config = PangeaConfig(domain=settings.PANGEA_DOMAIN)
audit = Audit(settings.PANGEA_AUDIT_TOKEN, config=config)

# create File Intel object
intel = FileIntel(settings.PANGEA_FILE_INTEL_TOKEN, config=config)

class GuestOnlyView(View):
    def dispatch(self, request, *args, **kwargs):
        # Redirect to the index page if the user already authenticated
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)

        return super().dispatch(request, *args, **kwargs)

class UploadView(FormView):
    template_name = 'accounts/upload_form.html'
    
    def get(self, request, *args, **kwargs):
        template_name = 'accounts/upload_form.html'
        form = DocumentForm()
        return render(request, template_name, {'form': form})
    
    def post(self, request, *args, **kwargs):
        template_name = 'accounts/upload_success.html'
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            # Calculate checksum of the file
            checksum = hashlib.md5(file.read()).hexdigest()
            file.seek(0)  # Seek back to start of file after reading
            
            # Now save the document instance manually without committing to database
            newdoc = form.save(commit=False)
            newdoc.checksum = checksum  # Set the calculated checksum
            newdoc.save()  # Now commit to the database

            #calling Pangea's file intel service with the filepath
            response = intel.filepathReputation(filepath= newdoc.file.path, provider="reversinglabs")

            request.session['file_verdict'] = response.result.data.verdict

            # Redirect to the document list after POST
            return render(request, template_name, {'form': form})
        else:
            print("Form not valid!!")
            template_name = 'accounts/upload_form.html'
            message = 'The form is not valid. Fix the following error:'
        return render(request, template_name, {'form': form})

    
    # def post(self, request, *args, **kwargs):
    #     template_name = 'accounts/upload_success.html'
    #     form = DocumentForm(request.POST, request.FILES)
    #     if form.is_valid():
    #         file = request.FILES['file']
    #         # Calculate checksum of the file
    #         checksum = hashlib.md5(file.read()).hexdigest()
    #         file.seek(0)  # Seek back to start of file after reading
    #         newdoc = Document(file=file, checksum=checksum)
    #         newdoc.save()

    #         #calling Pangea's file intel service with the filepath
    #         response = intel.filepathReputation(filepath= newdoc.file.path, provider="reversinglabs")

    #         request.session['file_verdict'] = response.result.data.verdict

    #         # Redirect to the document list after POST
    #         return render(request, template_name, {'form': form})
    #     else:
    #         print("Form not valid!!")
    #         template_name = 'accounts/upload_form.html'
    #         message = 'The form is not valid. Fix the following error:'
    #     return render(request, template_name, {'form': form})


from django.views.generic.list import ListView

class DocumentListView(ListView):
    model = Document
    template_name = 'accounts/file_list.html'
    context_object_name = 'documents'

    def get_queryset(self):
        return Document.objects.filter(user=self.request.user)
    
def serve_file(request, file_id):
    try:
        document = Document.objects.get(pk=file_id)
    except Document.DoesNotExist:
        return HttpResponse("File not found.", status=404)
        
    file_with_path = document.file.path
    file_to_download = open(file_with_path, 'rb')
    
    # Recalculate the checksum
    checksum = hashlib.md5(file_to_download.read()).hexdigest()
    file_to_download.seek(0)  # Seek back to start of file after reading
    
    if document.checksum != checksum:
        # The checksums do not match, alert the user.
        return HttpResponseBadRequest("File integrity check failed. The file might have been changed.")
        
    response = HttpResponse(file_to_download, content_type='application/force-download') 
    response['Content-Disposition'] = 'attachment; filename=%s' % document.file.name
    return response

class LogInView(GuestOnlyView, FormView):
    template_name = 'accounts/log_in.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.DISABLE_USERNAME or settings.LOGIN_VIA_EMAIL:
            return SignInViaEmailForm

        if settings.LOGIN_VIA_EMAIL_OR_USERNAME:
            return SignInViaEmailOrUsernameForm

        return SignInViaUsernameForm

    @method_decorator(sensitive_post_parameters('password'))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Sets a test cookie to make sure the user has cookies enabled
        request.session.set_test_cookie()

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        try :
            print('I entered the form')
            self.audit('Entering')
            request = self.request

            # If the test cookie worked, go ahead and delete it since its no longer needed
            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()

            # The default Django's "remember me" lifetime is 2 weeks and can be changed by modifying
            # the SESSION_COOKIE_AGE settings' option.
            if settings.USE_REMEMBER_ME:
                if not form.cleaned_data['remember_me']:
                    request.session.set_expiry(0)

            login(request, form.user_cache)
            print('request', request)
            if request.user.is_authenticated:
                #calling Pangea's Secure Audit Log
                audit.log("User: " +request.user.username+ " logged into the app!")

            redirect_to = request.POST.get(REDIRECT_FIELD_NAME, request.GET.get(REDIRECT_FIELD_NAME))
            url_is_safe = is_safe_url(redirect_to, allowed_hosts=request.get_host(), require_https=request.is_secure())

            if url_is_safe:
                return redirect(redirect_to)

            return redirect(settings.LOGIN_REDIRECT_URL)
        except Exception as e:
            print(f'Exception in form_valid: {e}')


class SignUpView(GuestOnlyView, FormView):
    template_name = 'accounts/sign_up.html'
    form_class = SignUpForm

    def form_valid(self, form):
        request = self.request
        user = form.save(commit=False)

        if settings.DISABLE_USERNAME:
            # Set a temporary username
            user.username = get_random_string()
        else:
            user.username = form.cleaned_data['username']

        if settings.ENABLE_USER_ACTIVATION:
            user.is_active = False

        # Create a user record
        user.save()

        # Change the username to the "user_ID" form
        if settings.DISABLE_USERNAME:
            user.username = f'user_{user.id}'
            user.save()

        if settings.ENABLE_USER_ACTIVATION:
            code = get_random_string(20)

            act = Activation()
            act.code = code
            act.user = user
            act.save()

            send_activation_email(request, user.email, code)

            messages.success(
                request, _('You are signed up. To activate the account, follow the link sent to the mail.'))
        else:
            raw_password = form.cleaned_data['password1']

            user = authenticate(username=user.username, password=raw_password)
            login(request, user)

            messages.success(request, _('You are successfully signed up!'))

        return redirect('index')


class ActivateView(View):
    @staticmethod
    def get(request, code):
        act = get_object_or_404(Activation, code=code)

        # Activate profile
        user = act.user
        user.is_active = True
        user.save()

        # Remove the activation record
        act.delete()

        messages.success(request, _('You have successfully activated your account!'))

        return redirect('accounts:log_in')


class ResendActivationCodeView(GuestOnlyView, FormView):
    template_name = 'accounts/resend_activation_code.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.DISABLE_USERNAME:
            return ResendActivationCodeViaEmailForm

        return ResendActivationCodeForm

    def form_valid(self, form):
        user = form.user_cache

        activation = user.activation_set.first()
        activation.delete()

        code = get_random_string(20)

        act = Activation()
        act.code = code
        act.user = user
        act.save()

        send_activation_email(self.request, user.email, code)

        messages.success(self.request, _('A new activation code has been sent to your email address.'))

        return redirect('accounts:resend_activation_code')


class RestorePasswordView(GuestOnlyView, FormView):
    template_name = 'accounts/restore_password.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.RESTORE_PASSWORD_VIA_EMAIL_OR_USERNAME:
            return RestorePasswordViaEmailOrUsernameForm

        return RestorePasswordForm

    def form_valid(self, form):
        user = form.user_cache
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        if isinstance(uid, bytes):
            uid = uid.decode()

        send_reset_password_email(self.request, user.email, token, uid)

        return redirect('accounts:restore_password_done')


class ChangeProfileView(LoginRequiredMixin, FormView):
    template_name = 'accounts/profile/change_profile.html'
    form_class = ChangeProfileForm

    def get_initial(self):
        user = self.request.user
        initial = super().get_initial()
        initial['first_name'] = user.first_name
        initial['last_name'] = user.last_name
        return initial

    def form_valid(self, form):
        user = self.request.user
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.save()

        messages.success(self.request, _('Profile data has been successfully updated.'))

        return redirect('accounts:change_profile')


class ChangeEmailView(LoginRequiredMixin, FormView):
    template_name = 'accounts/profile/change_email.html'
    form_class = ChangeEmailForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_initial(self):
        initial = super().get_initial()
        initial['email'] = self.request.user.email
        return initial

    def form_valid(self, form):
        user = self.request.user
        email = form.cleaned_data['email']

        if settings.ENABLE_ACTIVATION_AFTER_EMAIL_CHANGE:
            code = get_random_string(20)

            act = Activation()
            act.code = code
            act.user = user
            act.email = email
            act.save()

            send_activation_change_email(self.request, email, code)

            messages.success(self.request, _('To complete the change of email address, click on the link sent to it.'))
        else:
            user.email = email
            user.save()

            messages.success(self.request, _('Email successfully changed.'))

        return redirect('accounts:change_email')


class ChangeEmailActivateView(View):
    @staticmethod
    def get(request, code):
        act = get_object_or_404(Activation, code=code)

        # Change the email
        user = act.user
        user.email = act.email
        user.save()

        # Remove the activation record
        act.delete()

        messages.success(request, _('You have successfully changed your email!'))

        return redirect('accounts:change_email')


class RemindUsernameView(GuestOnlyView, FormView):
    template_name = 'accounts/remind_username.html'
    form_class = RemindUsernameForm

    def form_valid(self, form):
        user = form.user_cache
        send_forgotten_username_email(user.email, user.username)

        messages.success(self.request, _('Your username has been successfully sent to your email.'))

        return redirect('accounts:remind_username')


class ChangePasswordView(BasePasswordChangeView):
    template_name = 'accounts/profile/change_password.html'

    def form_valid(self, form):
        # Change the password
        user = form.save()

        # Re-authentication
        login(self.request, user)

        messages.success(self.request, _('Your password was changed.'))

        return redirect('accounts:change_password')


class RestorePasswordConfirmView(BasePasswordResetConfirmView):
    template_name = 'accounts/restore_password_confirm.html'

    def form_valid(self, form):
        # Change the password
        form.save()

        messages.success(self.request, _('Your password has been set. You may go ahead and log in now.'))

        return redirect('accounts:log_in')


class RestorePasswordDoneView(BasePasswordResetDoneView):
    template_name = 'accounts/restore_password_done.html'


class LogOutView(LoginRequiredMixin, BaseLogoutView):
    template_name = 'accounts/log_out.html'
