from django.shortcuts import render,redirect
from .models import *
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from PIL import Image
from django.urls import reverse

from django.conf import settings
from django.core.mail import send_mail
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.template import Context
from django.template.loader import render_to_string, get_template
from django.core.mail import EmailMessage

import random,uuid,base64
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic.edit import FormView
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.decorators.csrf import csrf_protect
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
)
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm,
)
import datetime
import re


# Create your views here.


def Register(request):
	if request.method == "POST":
		if UserProfile.objects.filter(mobile=request.POST['mobile']):
			messages.warning(request,"Mobile already linked with another account. Kindly login")
			return redirect('user-login')
		if UserProfile.objects.filter(email=request.POST['email']):
			messages.warning(request,"Email already linked with another account. Kindly login")
			return redirect('user-login')
		obj = User.objects.create_user(username=request.POST['email'],password=request.POST['pwd']
			,email=request.POST['email'])
		obj.save()		
		UserProfile(user = obj,name = request.POST['name'],mobile = request.POST['mobile']
			,email = request.POST['email'],pwd = request.POST['pwd']).save()
		messages.success(request,"கணக்கு வெற்றிகரமாக உருவாக்கப்பட்டது")
		return redirect('user-login')
	return render(request,"user/register.html",locals())

def Login(request):
	if request.method == "POST":
		if request.POST['formname'] == "email":
			if not UserProfile.objects.filter(email=request.POST['email']):
				messages.success(request,"கணக்கு இல்லை. புதிய கணக்கை உருவாக்க")
				return redirect('user-register')
			user = authenticate(username=request.POST['email'],password=request.POST['pwd'])
			if user is not None:
				login(request, user)
				messages.success(request, f'வரவேற்கிறோம் ராவணன் இ சேவை')
				return redirect('user-dashboard')
			else:
				messages.success(request, f'மின்னஞ்சல் அல்லது கடவுச்சொல் பொருந்தவில்லை')
				return redirect('user-login')
		if request.POST['formname'] == "otp":
			print(">>>>>>>>")
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if request.POST['eom'].isdigit():
				otp = str(uuid.uuid4().fields[-1])[:6]
				print(">>>>>>>>>>>>>>OTP",otp)
				try:
					if UserProfile.objects.get(mobile=str(request.POST['eom'])):
						# SMS API goes here
						txt = str(otp + request.POST['eom'])
						encode = txt.encode("ascii")
						encrypt = base64.b64encode(encode)
						decode = encrypt.decode("ascii")
						messages.success(request, "Verification code sent your mobile successfully!")
						return redirect('user-verify-otp-login', str(decode))
				except:
					messages.error(request, "Mobile Number Does not Exists")
					return redirect('user-login')

			if re.search(regex,request.POST['eom']):
				otp = str(uuid.uuid4().fields[-1])[:6]
				print(">>>>>>>>>>>>>>OTP",otp)
				try:
					if UserProfile.objects.get(email=str(request.POST['eom'])):
						message = "Your Login OTP is " + otp
						email_from = settings.EMAIL_HOST_USER
						recipient_list = [str(request.POST['eom'])]
						subject = "OTP From Orampoo Ecommerce"
						send_mail(subject, message, email_from, recipient_list)
						txt = str(otp + request.POST['eom'])
						encode = txt.encode("ascii")
						encrypt = base64.b64encode(encode)
						decode = encrypt.decode("ascii")
						messages.success(request, "Verification code sent your email successfully!")
						return redirect('user-verify-otp-login', str(decode))
				except:
					messages.error(request, "Mobile Number Does not Exists")
					return redirect('user-login')
	return render(request,"user/login.html",locals())

def Logout(request):
	if request.user.is_authenticated:
		logout(request)
		messages.success(request, f'நீங்கள் வெற்றிகரமாக வெளியேறிவிட்டீர்கள்')
		return redirect('user-login')

def forgotpass(request):
	if request.method == "POST":
		# otp = str(uuid.uuid4().fields[-1])[:6]
		regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
		if str(request.POST['eom']).isdigit():
			otp = str(uuid.uuid4().fields[-1])[:6]
			print("OTP is>>>>>>>>>>>>",otp)
			try:
				if UserProfile.objects.get(mobile=str(request.POST['eom'])):
					# SMS API goes here
					txt = str(otp + request.POST['eom'])
					encode = txt.encode("ascii")
					encrypt = base64.b64encode(encode)
					decode = encrypt.decode("ascii")
					messages.success(request, "Verification code sent your mobile successfully!")
					return redirect('user-verify-otp', str(decode))
			except:
				messages.error(request, "Mobile Number Does not Exists")
				return redirect('user-forgotpass')
		if re.search(regex,str(request.POST['eom'])):
			otp = str(uuid.uuid4().fields[-1])[:6]
			print("OTP is>>>>>>>>>>>>",otp)
			try:
				if UserProfile.objects.get(email=str(request.POST['eom'])):
					message = "Your Forgot Password OTP is " + otp
					email_from = settings.EMAIL_HOST_USER
					recipient_list = [str(request.POST['eom'])]
					subject = "Forgot Password From Orampoo Ecommerce"
					send_mail(subject, message, email_from, recipient_list)
					txt = str(otp + request.POST['eom'])
					encode = txt.encode("ascii")
					encrypt = base64.b64encode(encode)
					decode = encrypt.decode("ascii")
					messages.success(request, "ஒரு முறை கடவுச்சொல் வெற்றிகரமாக உங்கள் மின்னஞ்சலுக்கு அனுப்பப்பட்டது")
					return redirect('user-verify-otp', str(decode))
			except:
				messages.error(request, "மின்னஞ்சல் இல்லை")
				return redirect('user-forgotpass')
	return render(request,"user/forgotpass.html",locals())

def verify_otp(request,mobile):
	encode = str(mobile).encode("ascii")
	decrypt = base64.b64decode(encode)
	decode = decrypt.decode("ascii")
	mob1 = str(decode)[6:]
	otp = str(decode)[0:6]
	if request.method == "POST":
		if request.POST['formname'] == "login":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if otp == request.POST['otp']:
				if str(mob1).isdigit():
					pwd = UserProfile.objects.get(mobile=mob1)
					print("Your Passowrd is >>>>>>>>>>",pwd.pwd)
					# SMS API goes here
					messages.error(request, "Password sent your mobile successfully!")
					return redirect('user-login')
				if re.search(regex,str(mob1)):
					pwd = UserProfile.objects.get(email=str(mob1))
					print("Your Passowrd is >>>>>>>>>>",pwd.pwd)
					subject = "Forgot Password"
					msg = "Your Password is {}".format(pwd.pwd)
					email_from = settings.EMAIL_HOST_USER
					recipient_list = [pwd.email]
					send_mail(subject, msg, email_from, recipient_list)
					messages.error(request, "ஒரு முறை கடவுச்சொல் வெற்றிகரமாக உங்கள் மின்னஞ்சலுக்கு அனுப்பப்பட்டது")
					return redirect('user-login')
			else:
				messages.error(request, "Wrong OTP!")
				return redirect('user-verify-otp', mobile)
		if request.POST['formname'] == "resend":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if str(mob1).isdigit():
				print("Mobile OTP>>>>>>>>",otp)
				# SMS API goes here
				messages.error(request, "OTP sent your mobile successfully!")
				return redirect('user-verify-otp', mobile)
			if re.search(regex,str(mob1)):
				print("Email OTP>>>>>>>>",otp)
				message = "Your Login OTP is " + otp
				email_from = settings.EMAIL_HOST_USER
				recipient_list = [str(mob1)]
				subject = "OTP From Orampoo Ecommerce"
				send_mail(subject, message, email_from, recipient_list)
				messages.error(request, "ஒரு முறை கடவுச்சொல் வெற்றிகரமாக உங்கள் மின்னஞ்சலுக்கு அனுப்பப்பட்டது")
				return redirect('user-verify-otp', mobile)
	return render(request,"user/verifyotp.html",locals())

def verify_otp_login(request,mobile):
	encode = str(mobile).encode("ascii")
	decrypt = base64.b64decode(encode)
	decode = decrypt.decode("ascii")
	mob1 = str(decode)[6:]
	otp = str(decode)[0:6]
	if request.method == "POST":
		if request.POST['formname'] == "login":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if otp == request.POST['otp']:
				if str(mob1).isdigit():
					usr = UserProfile.objects.get(mobile=mob1)
					user = authenticate(username=usr.email,password=usr.pwd)
					if user is not None:
						login(request, user)
						messages.error(request, "Welcome to Orampoo!")
						return redirect('user-dashboard')
				if re.search(regex,str(mob1)):
					usr = UserProfile.objects.get(email=str(mob1))				
					user = authenticate(username=usr.email,password=usr.pwd)
					if user is not None:
						login(request, user)
						messages.error(request, "Welcome to Orampoo!")
						return redirect('user-dashboard')
			else:
				messages.error(request, "Wrong OTP!")
				return redirect('user-verify-otp-login', mobile)
		if request.POST['formname'] == "resend":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if str(mob1).isdigit():
				# SMS API goes here
				print("Mobile OTP>>>>>>>>",otp)
				messages.error(request, "OTP sent your mobile successfully!")
				return redirect('user-verify-otp-login', mobile)
			if re.search(regex,str(mob1)):
				print("Email OTP>>>>>>>>",otp)
				message = "Your Login OTP is " + otp
				email_from = settings.EMAIL_HOST_USER
				recipient_list = [str(mob1)]
				subject = "OTP From Orampoo Ecommerce"
				send_mail(subject, message, email_from, recipient_list)
				messages.error(request, "OTP sent your email successfully!")
				return redirect('user-verify-otp-login', mobile)
	return render(request,"user/verifyotp.html",locals())

class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'title': self.title,
            **(self.extra_context or {})
        })
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
	form_class = PasswordChangeForm
	success_url = reverse_lazy('user-password-change-done')
	template_name = 'user/password_change_form.html'
	title = _('Password change')

	@method_decorator(sensitive_post_parameters())
	@method_decorator(csrf_protect)
	@method_decorator(login_required)
	def dispatch(self, *args, **kwargs):
		return super().dispatch(*args, **kwargs)

	def get_form_kwargs(self):
		kwargs = super().get_form_kwargs()
		kwargs['user'] = self.request.user
		user = UserProfile.objects.get(user = self.request.user)
		if self.request.method == "POST":
			if self.request.POST.get('old_password') != user.pwd:
				messages.success(self.request,"தற்போதைய கடவுச்சொல் தவறானது")
			if self.request.POST.get('new_password1') != self.request.POST.get('new_password2'):
				messages.success(self.request,"புதிய கடவுச்சொல் மற்றும் உறுதி கடவுச்சொல் பொருந்தவில்லை!")
		return kwargs

	def form_valid(self, form):
		user = UserProfile.objects.get(user = form.user)
		data = self.request.POST.get('new_password2')
		user.pwd = data
		user.save()
		form.save()
		message = "உங்கள் கடவுச்சொல் வெற்றிகரமாக மாற்றப்பட்டது"
		email_from = settings.EMAIL_HOST_USER
		recipient_list = [user.email]
		subject = "உங்கள் கடவுச்சொல் வெற்றிகரமாக மாற்றப்பட்டது"
		send_mail(subject, message, email_from, recipient_list)
		update_session_auth_hash(self.request, form.user)
		return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = 'user/password_change_done.html'
    title = _('Password change successful')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


def profile(request):
	obj = UserProfile.objects.get(user = request.user)
	if request.method == "POST":
		if request.POST['formname'] == "profile-update":
			obj.name = request.POST['name']
			obj.email = request.POST['email']
			obj.mobile = request.POST['mobile']
			obj.mobile1 = request.POST['mobile1']
			obj.address = request.POST['address']
			obj.save()
			messages.success(request,"சுயவிவரம் வெற்றிகரமாகப் புதுப்பிக்கப்பட்டது")
			return redirect("user-profile")
	return render(request,"user/profile.html",locals())

def dash(request):
	if request.user.is_authenticated:
		if request.method == "POST":
			if request.POST['formname'] == "service-req":
				Service(user = request.user, job = request.POST['job'], desc = request.POST['desc'], 
					bname = request.POST['bname'],mobile = request.POST['mobile'], 
					mobile1 = request.POST['mobile1'],email = request.POST['email'],
					address = request.POST['address']).save()
				messages.success(request,"சேவை வெற்றிகரமாக கோரப்பட்டது")
				return redirect('user-dashboard')
		return render(request,"user/dash.html",locals())
	else:
		# messages.success(request,"Kindly Login First!")
		return redirect('user-login')

def service_history(request,):
	obj = Service.objects.filter(user = request.user)[::-1]
	if request.method == "POST":
		if request.POST['formname'] == "document-upload":
			o = Service.objects.get(id = request.POST['idd'])
			o.docname += request.POST['name']+str(",")
			o.save()
			Documents(service = o, name = request.POST['name'], docno = request.POST['docno'], 
				doc = request.FILES['doc']).save()
			messages.success(request,"ஆவணம் வெற்றிகரமாக பதிவேற்ற பட்டது")
			return redirect('user-service-history')
	return render(request,"user/service-history.html",locals())