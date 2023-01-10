from django.shortcuts import render,redirect
from requests import Session
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from PIL import Image
from django.urls import reverse

from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import EmailMessage
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from django.template import Context
from django.template.loader import render_to_string, get_template

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
import csv
import os
from pathlib import Path
from django.http import HttpResponse
from PIL import Image, ImageDraw, ImageFont

from io import BytesIO
from django.template.loader import get_template
from django.views import View
from xhtml2pdf import pisa
from pdf2image import convert_from_path
from django.core.paginator import Paginator
from django.http import FileResponse, Http404

from django.contrib.auth.hashers import make_password, check_password
fromaddr = settings.EMAIL_HOST_USER
password = settings.EMAIL_HOST_PASSWORD
def Register(request):
	if request.method == "POST":
		if AdminProfile.objects.filter(mobile=request.POST['mobile']):
			messages.warning(request,"Mobile already linked with another account. Kindly login")
			return redirect('sadmin-login')
		if User.objects.filter(email=request.POST['email']):
			messages.warning(request,"Email already linked with another account. Kindly login")
			return redirect('sadmin-login')
		obj = User.objects.create_user(
			first_name=request.POST['firstname'],
			last_name=request.POST['lastname'],
			username=request.POST['email'],
			password=request.POST['pwd'],
			email=request.POST['email']
			)
		#set by default newly register user as in active
		obj.is_active = False
		obj.save()		
		AdminProfile(user = obj,mobile = request.POST['mobile']).save()
		messages.success(request,"You account successfully created")
		return redirect('sadmin-login')
	return render(request,"sadmin/register.html",locals())

def Login(request):
	if request.method == "POST":
		if request.POST['formname'] == "email":
			# if not AdminProfile.objects.filter(email=request.POST['email']):
			# 	messages.success(request,"கணக்கு இல்லை. புதிய கணக்கை உருவாக்க")
			# 	return redirect('sadmin-register')
			user = authenticate(username=request.POST['email'],password=request.POST['pwd'])
			if user is not None:
				#get logged in user permission/access list
				get_user_permission_details(request,user)
				login(request, user)
				messages.success(request, f'Welcome to Ravanan People E-Service Center')
				return redirect('sadmin-dashboard')
			else:
				messages.success(request, f'Email or Username does not exists')
				return redirect('sadmin-login')
		if request.POST['formname'] == "otp":
			print(">>>>>>>>")
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if request.POST['eom'].isdigit():
				otp = str(uuid.uuid4().fields[-1])[:6]
				print(">>>>>>>>>>>>>>OTP",otp)
				try:
					if AdminProfile.objects.get(mobile=str(request.POST['eom'])):
						# SMS API goes here
						txt = str(otp + request.POST['eom'])
						encode = txt.encode("ascii")
						encrypt = base64.b64encode(encode)
						decode = encrypt.decode("ascii")
						messages.success(request, "Verification code sent your mobile successfully!")
						return redirect('sadmin-verify-otp-login', str(decode))
				except:
					messages.error(request, "Mobile Number Does not Exists")
					return redirect('sadmin-login')

			if re.search(regex,request.POST['eom']):
				otp = str(uuid.uuid4().fields[-1])[:6]
				print(">>>>>>>>>>>>>>OTP",otp)
				try:
					if AdminProfile.objects.get(email=str(request.POST['eom'])):
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
						return redirect('sadmin-verify-otp-login', str(decode))
				except:
					messages.error(request, "Mobile Number Does not Exists")
					return redirect('sadmin-login')
	return render(request,"sadmin/login.html",locals())

def Logout(request):
	if request.user.is_authenticated:
		logout(request)
		messages.success(request, f'You have successfully logged out')
		return redirect('sadmin-login')

def forgotpass(request):
	if request.method == "POST":
		# otp = str(uuid.uuid4().fields[-1])[:6]
		regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
		if str(request.POST['eom']).isdigit():
			otp = str(uuid.uuid4().fields[-1])[:6]
			print("OTP is>>>>>>>>>>>>",otp)
			try:
				if AdminProfile.objects.get(mobile=str(request.POST['eom'])):
					# SMS API goes here
					txt = str(otp + request.POST['eom'])
					encode = txt.encode("ascii")
					encrypt = base64.b64encode(encode)
					decode = encrypt.decode("ascii")
					messages.success(request, "Verification code sent your mobile successfully!")
					return redirect('sadmin-verify-otp', str(decode))
			except:
				messages.error(request, "Mobile Number Does not Exists")
				return redirect('sadmin-forgotpass')
		if re.search(regex,str(request.POST['eom'])):
			otp = str(uuid.uuid4().fields[-1])[:6]
			print("OTP is>>>>>>>>>>>>",otp)
			print("email ", str(request.POST['eom']))
			try:
				if AdminProfile.objects.get(email=str(request.POST['eom'])):
					message = "Your Forgot Password OTP is " + otp
					email_from = settings.EMAIL_HOST_USER
					recipient_list = [str(request.POST['eom'])]
					subject = "Forgot Password From NTK Veerapandi"
					send_mail(subject, message, email_from, recipient_list)
					txt = str(otp + request.POST['eom'])
					encode = txt.encode("ascii")
					encrypt = base64.b64encode(encode)
					decode = encrypt.decode("ascii")
					messages.success(request, "One time password has been sent to your email")
					return redirect('sadmin-verify-otp', str(decode))
			except:
				messages.error(request, "மின்னஞ்சல் இல்லை")
				return redirect('sadmin-forgotpass')
	return render(request,"sadmin/forgotpass.html",locals())

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
					pwd = AdminProfile.objects.get(mobile=mob1)
					print("Your Passowrd is >>>>>>>>>>",pwd.pwd)
					# SMS API goes here
					messages.error(request, "Password sent your mobile successfully!")
					return redirect('sadmin-login')
				if re.search(regex,str(mob1)):
					pwd = AdminProfile.objects.get(email=str(mob1))
					print("Your Passowrd is >>>>>>>>>>",pwd.pwd)
					subject = "Forgot Password"
					msg = "Your Password is {}".format(pwd.pwd)
					email_from = settings.EMAIL_HOST_USER
					recipient_list = [pwd.email]
					send_mail(subject, msg, email_from, recipient_list)
					messages.error(request, "One time password has been sent to your email")
					return redirect('sadmin-login')
			else:
				messages.error(request, "Wrong OTP!")
				return redirect('sadmin-verify-otp', mobile)
		if request.POST['formname'] == "resend":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if str(mob1).isdigit():
				print("Mobile OTP>>>>>>>>",otp)
				# SMS API goes here
				messages.error(request, "OTP sent your mobile successfully!")
				return redirect('sadmin-verify-otp', mobile)
			if re.search(regex,str(mob1)):
				print("Email OTP>>>>>>>>",otp)
				message = "Your Login OTP is " + otp
				email_from = settings.EMAIL_HOST_USER
				recipient_list = [str(mob1)]
				subject = "OTP From NTK Veerapandi"
				send_mail(subject, message, email_from, recipient_list)
				messages.error(request, "One time password has been sent to your email")
				return redirect('sadmin-verify-otp', mobile)
	return render(request,"sadmin/verifyotp.html",locals())

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
					usr = AdminProfile.objects.get(mobile=mob1)
					user = authenticate(username=usr.email,password=usr.pwd)
					if user is not None:
						login(request, user)
						messages.error(request, "Welcome to Orampoo!")
						return redirect('sadmin-dashboard')
				if re.search(regex,str(mob1)):
					usr = AdminProfile.objects.get(email=str(mob1))				
					user = authenticate(username=usr.email,password=usr.pwd)
					if user is not None:
						login(request, user)
						messages.error(request, "Welcome to Orampoo!")
						return redirect('sadmin-dashboard')
			else:
				messages.error(request, "Wrong OTP!")
				return redirect('sadmin-verify-otp-login', mobile)
		if request.POST['formname'] == "resend":
			regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
			if str(mob1).isdigit():
				# SMS API goes here
				print("Mobile OTP>>>>>>>>",otp)
				messages.error(request, "OTP sent your mobile successfully!")
				return redirect('sadmin-verify-otp-login', mobile)
			if re.search(regex,str(mob1)):
				print("Email OTP>>>>>>>>",otp)
				message = "Your Login OTP is " + otp
				email_from = settings.EMAIL_HOST_USER
				recipient_list = [str(mob1)]
				subject = "OTP From Orampoo Ecommerce"
				send_mail(subject, message, email_from, recipient_list)
				messages.error(request, "OTP sent your email successfully!")
				return redirect('sadmin-verify-otp-login', mobile)
	return render(request,"sadmin/verifyotp.html",locals())

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
	success_url = reverse_lazy('sadmin-password-change-done')
	template_name = 'sadmin/password_change_form.html'
	title = _('Password change')

	@method_decorator(sensitive_post_parameters())
	@method_decorator(csrf_protect)
	@method_decorator(login_required)
	def dispatch(self, *args, **kwargs):
		return super().dispatch(*args, **kwargs)

	def get_form_kwargs(self):
		kwargs = super().get_form_kwargs()
		kwargs['user'] = self.request.user
		user = AdminProfile.objects.get(user = self.request.user)
		if self.request.method == "POST":
			if self.request.POST.get('old_password') != user.pwd:
				messages.success(self.request,"Current password is wrong")
			if self.request.POST.get('new_password1') != self.request.POST.get('new_password2'):
				messages.success(self.request,"New password or username is not correct")
		return kwargs

	def form_valid(self, form):
		user = AdminProfile.objects.get(user = form.user)
		data = self.request.POST.get('new_password2')
		user.pwd = data
		user.save()
		form.save()
		message = "Succesfully password has been changed."
		email_from = settings.EMAIL_HOST_USER
		recipient_list = [user.email]
		subject = "Succesfully password has been changed."
		send_mail(subject, message, email_from, recipient_list)
		update_session_auth_hash(self.request, form.user)
		return super().form_valid(form)

class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = 'sadmin/password_change_done.html'
    title = _('Password change successful')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

def dash(request):
	if request.user.is_authenticated:
		print(">>>>>>>>>>>>>>>",request.user.first_name)
		is_ration_access = request.session.get("is_ration_access")
		is_aadhar_access = request.session.get("is_aadhar_access")
		is_pan_access = request.session.get("is_pan_access")
		is_welfare_access = request.session.get("is_welfare_access")
		is_ithara_access = request.session.get("is_ithara_access")
		is_voter_access = request.session.get("is_voter_access")
		is_view_only = request.session.get("is_view_only")

		obj = Service.objects.all()[:5]
		if request.method == "POST":
			print("------------------------------",request.POST['form_name'])
			if request.POST['form_name'] == "newServiceFrom":
				print("1111111111111111111111111111111111111111111111111111111")
				try:
					job = request.POST['works']
				except:
					job = "Null"
				try:
					ondriyam = 	request.POST['taluk']
				except:
					ondriyam = "Null"
				try:
					oor =  request.POST['ஒன்றியம்']
				except:
					oor = "Null"
				try:
					oratchi = request.POST['ஊர் பெயர்கள்']
				except:
					oratchi = "Null"
				
			
				# 	 must required
				try:
					ondriyam = request.POST['taluk']
				except:
					messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
					return redirect('sadmin-dashboard')
				try:
					Service(
					user = request.user,
					jobtit = request.POST['workTitle'],
					job = job,
					ithura = request.POST['ithura'],
					shopno = request.POST['kadaiNum'],
					refno = request.POST['NoteNum'],
					refdoc = request.FILES['upData'],
					amount = request.POST['cash'],
					bname = request.POST['benName'],
					regmob = request.POST['RegConNum'],
					conmob = request.POST['conNum'],
					email = request.POST['benMail'],
					ondriyam = request.POST['taluk'],
					other = request.POST['others_1'],
					oor = oor,
					oratchi = oratchi,
					theru = request.POST['streeName'],
					date = datetime.datetime.now()
					
					).save()
				except:
					Service(
					user = request.user,
					jobtit = request.POST['workTitle'],
					job = job,
					ithura = request.POST['ithura'],
					shopno = request.POST['kadaiNum'],
					refno = request.POST['NoteNum'],
					# refdoc = request.FILES['upData'],
					amount = request.POST['cash'],
					bname = request.POST['benName'],
					regmob = request.POST['RegConNum'],
					conmob = request.POST['conNum'],
					email = request.POST['benMail'],
					ondriyam = request.POST['taluk'],
					other = request.POST['others_1'],
					oor = oor,
					oratchi = oratchi,
					theru = request.POST['streeName'],
					date = datetime.datetime.now()
					
					).save()
				
				name = request.POST["benName"]
				refno = request.POST['NoteNum']
				jobtit = job
				amount = request.POST['cash']
				date =  datetime.datetime.now()
				email = request.POST['benMail']
				try:
					user = AdminProfile.objects.get(user = request.user)
				except:None
				from pathlib import Path
				import os
				BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"

				template = get_template("sadmin/cert.html")
				html  = template.render(locals())
				import subprocess

				wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                                   "--print-media-type",
									   "--enable-local-file-access",
	                                   "--encoding",
	                                   "UTF-8",
	                                   "-",
	                                   "-"),
	                                  stdin=subprocess.PIPE,
	                                  stdout=subprocess.PIPE)
				wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
				pdf = wkdata[0]
				

				data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
				data.write(pdf)
				data.close()
				# ====================================================================
				try:
					toaddr = email
					msg = MIMEMultipart() 
					msg['From'] = fromaddr 
					msg['To'] = toaddr
					msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
					body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.
						உங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
					msg.attach(MIMEText(body, 'plain'))
					filename = "{}/certificate.pdf".format(BASE_DIR)
					attachment = open(filename, "rb")
					p = MIMEBase('application', 'octet-stream')
					p.set_payload((attachment).read())
					encoders.encode_base64(p)
					p.add_header('Content-Disposition', "attachment; filename=cert.pdf")
					msg.attach(p)
					s = smtplib.SMTP('smtp.gmail.com', 587)
					s.starttls()
					s.login(fromaddr, password)
					text = msg.as_string()
					s.sendmail(fromaddr, toaddr, text)
					s.quit()
					# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
					obj = Service.objects.all()
					print("222222222222222222222222222222222222222222222222222222")
					return render(request,"sadmin/dash.html",locals())

				except:
					obj = Service.objects.all()
					messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
					return render(request,"sadmin/dash.html",locals())

			if request.POST['form_name'] == "edit":
				obj = Service.objects.get(id = request.POST['idd'])
				obj.refno = request.POST['NoteNum']
				try:
					obj.refdoc = request.FILES['upData']
				except:pass
				obj.bname = request.POST['benName']
				obj.regmob = request.POST['RegConNum']
				obj.conmob = request.POST['conNum']
				obj.email = request.POST['benMail']
				obj.save()
				messages.success(request,"Record Updated Successfully")
				return redirect('sadmin-dashboard')
			if request.POST['form_name'] == "del":
				obj = Service.objects.get(id = request.POST['idd'])
				obj.delete()
				messages.success(request,"Record Deleted Successfully")
				return redirect('sadmin-dashboard')

			if request.POST['form_name'] == "filter":
				if request.POST['workTitle'] == "All":
					obj = Service.objects.all()
			
				else:
					obj = Service.objects.filter(jobtit = request.POST['workTitle'])[::-1]
			if request.POST['form_name'] == "subFilter2":
				print("1111111111111111111111111111111111111111111111111     ",request.POST['works2'])
				qur_str = "SELECT * FROM webapp_service WHERE '{}' in (job);".format(request.POST['works2'])	
				obj = Service.objects.raw(qur_str)
				# if len(obj) <= 0:
				# 	messages.error(request, "தரவு காணப்படவில்லை")
				# 	return redirect('/')
				
				# search by mobile and kuripu en
			if request.POST["form_name"] == "srhList":
				if str(request.POST['searchList']).isnumeric() and len(str(request.POST['searchList'])) == 10 :
					# print("khdskahdkhasdkh     ", request.POST['searchList'])
					obj = Service.objects.filter(regmob = request.POST['searchList'])
					# return render(request,"sadmin/getmore.html",locals())

				elif request.POST['searchList']:
					
					
					qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno,  refno, bname, regmob, conmob,oor,theru );".format(request.POST['searchList'])
					
					obj = Service.objects.raw(qur_str)
		

					# if 
					# obj = Service.objects.values_list(str(request.POST['searchList']), flat=True)
					# if len(obj) <= 0:
					# 	messages.error(request, "தரவு காணப்படவில்லை")
					# 	return redirect('/')
					
					# else:
					# 	obj = obj
					
					# obj = Service.objects.filter(email = request.POST['searchList'])
					# if len(obj) <= 0:
					# 	messages.error(request, "தரவு காணப்படவில்லை")
					# 	return redirect('/')
					
					# else:
			# obj = obj 
						
			# contact_list = obj
			# paginator = Paginator(contact_list, 2) # Show 25 contacts per page.

			# page_number = request.GET.get('page')
			# page_obj = paginator.get_page(page_number)

		
		return render(request,"sadmin/dash.html",locals())
	else:
		# messages.success(request,"Kindly Login First!")
		return redirect('sadmin-login')

def getmore(request):
	# usr = AdminProfile.objects.get(user = request.user)
	# print("==============================",usr.sadmin)
	obj = Service.objects.all()
	if request.method == "POST":
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			obj.refno = request.POST['RegConNum']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)
			obj.lstUser = request.user.first_name
			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('sadmin-getmore')
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('sadmin-getmore')
		if request.POST['form_name'] == "filter":
			if request.POST['workTitle'] == "All":
				obj = Service.objects.all()
			
			else:
				obj = Service.objects.filter(jobtit = request.POST['workTitle'])[::-1]
				
		# sub form filture
		if request.POST['form_name'] == "subFilter2":
			print("1111111111111111111111111111111111111111111111111     ",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (job);".format(request.POST['works2'])	
			obj = Service.objects.raw(qur_str)

		# search by mobile and kuripu en
		if request.POST["form_name"] == "srhList":
			if str(request.POST['searchList']).isnumeric() and len(str(request.POST['searchList'])) == 10 :
					# print("khdskahdkhasdkh     ", request.POST['searchList'])
				obj = Service.objects.filter(regmob = request.POST['searchList'])
					# return render(request,"sadmin/getmore.html",locals())

			elif request.POST['searchList']:
					
					
				qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])
					
				obj = Service.objects.raw(qur_str)
		

					# if 
					# obj = Service.objects.values_list(str(request.POST['searchList']), flat=True)
					# if len(obj) <= 0:
					# 	messages.error(request, "தரவு காணப்படவில்லை")
					# 	return redirect('/')
					
					# else:
					# 	obj = obj
					
					# obj = Service.objects.filter(email = request.POST['searchList'])
					# if len(obj) <= 0:
					# 	messages.error(request, "தரவு காணப்படவில்லை")
					# 	return redirect('/')
					
					# else:

		if request.POST["form_name"] == "CHECK":
			name = request.POST["benName"]
			refno = request.POST["NoteNum"]
			jobtit = request.POST["workTitle"]
			amount = request.POST["cash"]
			date =  datetime.datetime.now()
			email = request.POST["benMail"]
			user = AdminProfile.objects.get(user = request.user)


			# print(user[1])




			# stor = render(request,"sadmin/cert.html",locals())

			from pathlib import Path
			import os

			
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"

			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
                                   "--print-media-type",
								   "--enable-local-file-access",
                                   "--encoding",
                                   "UTF-8",
                                   "-",
                                   "-"),
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			

			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			# ====================================================================
			# fromaddr = "palaniarun8@gmail.com"
			# toaddr = email
			# msg = MIMEMultipart() 
			# msg['From'] = fromaddr 
			# msg['To'] = toaddr
			# msg['Subject'] = "Subject of the Mail"
			# body = "ராவணன் இ சேவை"
			# msg.attach(MIMEText(body, 'plain'))
			# filename = "{}/certificate.pdf".format(BASE_DIR)
			# attachment = open(filename, "rb")
			# p = MIMEBase('application', 'octet-stream')
			# p.set_payload((attachment).read())
			# encoders.encode_base64(p)
			# p.add_header('Content-Disposition', "attachment; filename=cert.pdf")
			# msg.attach(p)
			# s = smtplib.SMTP('smtp.gmail.com', 587)
			# s.starttls()
			# s.login(fromaddr, "Aarun@#6489@#a")
			# text = msg.as_string()
			# s.sendmail(fromaddr, toaddr, text)
			# s.quit()
			# ====================================================================

			response = HttpResponse(content_type='application/pdf')
			response['Content-Disposition'] = 'filename={}.pdf'.format("filename")
			
			response.write(pdf)

			return response
			# return stor
		# if request.POST["form_name"] == "send_Certi":
		# 	return 
		if request.POST["form_name"] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST["workTitle"]
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certificate.pdf".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.pdf")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = Service.objects.all()
				print("222222222222222222222222222222222222222222222222222222")
				return render(request,"sadmin/getmore.html",locals())
			except:
				obj = Service.objects.all()
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return render(request,"sadmin/getmore.html",locals())

			

			# print(user[1])




			# stor = render(request,"sadmin/cert.html",locals())

			from pathlib import Path
			import os

			
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"

			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
                                   "--print-media-type",
								   "--enable-local-file-access",
                                   "--encoding",
                                   "UTF-8",
                                   "-",
                                   "-"),
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			

			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			# ====================================================================
			# fromaddr = "palaniarun8@gmail.com"
			# toaddr = email
			# msg = MIMEMultipart() 
			# msg['From'] = fromaddr 
			# msg['To'] = toaddr
			# msg['Subject'] = "Subject of the Mail"
			# body = "ராவணன் இ சேவை"
			# msg.attach(MIMEText(body, 'plain'))
			# filename = "{}/certificate.pdf".format(BASE_DIR)
			# attachment = open(filename, "rb")
			# p = MIMEBase('application', 'octet-stream')
			# p.set_payload((attachment).read())
			# encoders.encode_base64(p)
			# p.add_header('Content-Disposition', "attachment; filename=cert.pdf")
			# msg.attach(p)
			# s = smtplib.SMTP('smtp.gmail.com', 587)
			# s.starttls()
			# s.login(fromaddr, "Aarun@#6489@#a")
			# text = msg.as_string()
			# s.sendmail(fromaddr, toaddr, text)
			# s.quit()
			# ====================================================================

			response = HttpResponse(content_type='application/pdf')
			response['Content-Disposition'] = 'filename={}.pdf'.format("filename")
			
			response.write(pdf)

			return response
		
		if request.POST["form_name"] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("All-data",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.all()
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response

		paginator = Paginator(obj, 2)
		page_number = request.GET.get('page')
		page_obj = paginator.get_page(page_number)


			
	return render(request,"sadmin/getmore.html",locals())

def downCsv(request):
		
	output = []
	response = HttpResponse (content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename='
	writer = csv.writer(response)
	query_set = Service.objects.all()
	titles = ["user","jobno","jobtit","job","ithura","shopno","refno","amount","bname","regmob","conmob","email","ondriyam","other","oor","oratchi","theru","status","date","approve"]
	writer.writerow(titles)
	for obj in query_set:	
		output.append([obj.user,obj.jobno,obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])

	writer.writerows(output)
	return response

def get_user_permission_details(request,user):
		permission_list =  user.get_all_permissions() 
		#incase user permission set is empty then consider view only permission for all services
		if len(permission_list) > 0:
			is_view_only = 'webapp.view_servicelinks' in permission_list
			is_ration_access = 'webapp.Ration' in permission_list
			is_aadhar_access = 'webapp.Aadhar' in permission_list
			is_pan_access = 'webapp.Pan' in permission_list
			is_welfare_access = 'webapp.Welfare' in permission_list
			is_voter_access = 'webapp.Voter' in permission_list
			is_ithara_access = 'webapp.Ithara' in permission_list
		else:
			is_view_only = False
			is_ration_access = True
			is_aadhar_access = True
			is_pan_access = True
			is_welfare_access = True
			is_voter_access = True
			is_ithara_access = True
		
		request.session["is_view_only"] = is_view_only
		request.session["is_ration_access"] = is_ration_access
		request.session["is_aadhar_access"] = is_aadhar_access
		request.session["is_pan_access"] = is_pan_access
		request.session["is_welfare_access"] = is_welfare_access
		request.session["is_voter_access"] = is_voter_access
		request.session["is_ithara_access"] = is_ithara_access

def r_card(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='Ration Card' ;"	
	obj = Service.objects.raw(qur_str)[::-1] #show all records except last one in case show few add this [:n] where is number
	obj_lnk = ServiceLinks.objects.all()
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")
	total_records = len(obj)
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['Town']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['VillageName']
			except:
				oratchi = "Null"
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---Please select Town---")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				).save()
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr
				msg['To'] = toaddr
				msg['Subject'] = "Ravanan People E-Service Center"
				body = """ You {} Request has been successfully received.\n\nYour receipt number :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"Could not send Email")
				return redirect('ration')
		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('ration')
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			obj.refno = request.POST['RegConNum']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('Town',obj.oor)
			obj.oratchi = request.POST.get('Village',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)
			obj.lstUser = request.user.first_name
			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('ration')
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			try:
				with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
					return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "Ravanam People E-Service Center"
				body = """ Your {} Request has been successfully received.\n\nYour reference # :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"Could not send email")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","Job title","Job","Other","Shop","Note","Amount","Beneficiary Name","Mobile","Contact","Email","Town","Other","Village","Headvillage","Street","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response

	return render(request,"sadmin/ration.html",locals())

def aadhar(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='ஆதார்' ;"	
	obj = Service.objects.raw(qur_str)[::-1]
	obj_lnk = ServiceLinks.objects.all()
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")
	total_records = len(obj)
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['ஒன்றியம்']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['ஊர் பெயர்கள்']
			except:
				oratchi = "Null"
			
		
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
						
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return redirect('aadhar')
		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["ஆதார் முகவரி மாற்றம்", "ஆதார் பெயர் மாற்றம்", "ஆதார் அகவை நாள் மாற்றம்", "ஆதார் முகவரி (ம) பெயர் மாற்றம்", "ஆதார் அகவை நாள், (ம) முகவரி மாற்றம்பம்", "ஆதார் அகவை நாள், (ம) பெயர், மாற்றம்", "ஆதார் அகவை நாள், பெயர், (ம) முகவரி மாற்றம்", "ஆதார் பாலினம் மாற்றம்"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())	
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('aadhar')	
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			obj.refno = request.POST['RegConNum']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)
			obj.lstUser = request.user.first_name
			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('ration')
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			try:
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response
	
	return render(request,"sadmin/aadhar.html",locals())
#பாண் கர்ட் தகவல்
def pan(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='பான்' ;"	
	obj = Service.objects.raw(qur_str)[::-1]
	obj_lnk = ServiceLinks.objects.all()
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")	
	total_records = len(obj)		
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['ஒன்றியம்']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['ஊர் பெயர்கள்']
			except:
				oratchi = "Null"
			
		
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
									
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return redirect('pan')


		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய பான் அட்டை விண்ணப்பம்", "பான் எண்ணை ஆதாரில் இணைத்தால்", "நகல் பான் அட்டை", "பான் அட்டையில் அகவை நாள் மாற்றம்", "பான் அட்டையில் பெயர் மாற்றம்", "பான் அட்டையில் புகைப்படம் மாற்றம்", "பான் அட்டையில் கையெழுத்து புதுபித்தல்", "பான் அட்டையில் சிறியவரிலிருந்து பெரியவர்"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)
			obj.lstUser = request.user.first_name
			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('ration')
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('pan')
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			try:
				with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
					return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response
	return render(request,"sadmin/pan.html",locals())
def welfar(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='நலவாரியம்' ;"	
	obj = Service.objects.raw(qur_str)[::-1]
	obj_lnk = ServiceLinks.objects.all()	
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")
	total_records = len(obj)
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['ஒன்றியம்']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['ஊர் பெயர்கள்']
			except:
				oratchi = "Null"
			
		
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
									
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return redirect('Welfare')

		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["நலவாரியம் புதுப்பித்தல்", "நலவாரியம் விண்ணப்பித்தால்"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)

			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('Welfare')		
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('Welfare')
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			try:
				with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
					return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response
	return render(request,"sadmin/welfar.html",locals())
	# qur_str = "SELECT * FROM webapp_service WHERE job == பான்;"

def voter_id(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='வாக்காளர் அட்டை' ;"	
	obj = Service.objects.raw(qur_str)[::-1]	
	obj_lnk = ServiceLinks.objects.all()
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")	
	total_records = len(obj)
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['ஒன்றியம்']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['ஊர் பெயர்கள்']
			except:
				oratchi = "Null"
			
		
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
									
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return redirect('Voter-card')

		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய வாக்காளர் அட்டை விண்ணப்பம் புதுப்பித்தல்", "வாக்காளர் அட்டையில் முகவரி மாற்றம்", "நகல் வாக்காளர் அட்டை விண்ணப்பம்", "வாக்காளர் அட்டையில் பெயர் மாற்றம்", "வாக்காளர் அட்டையில் அகவை நாள் மாற்றம்", "வாக்காளர் அட்டையில் புகைப்படம் மாற்றம்", "வாக்காளர் அட்டையில் உறவு முறை பெயர் மாற்றம்", "வாக்காளர் அட்டையில் தொகுதி மாற்றம்"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			obj.refno = request.POST['RegConNum']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)
			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('ration')		
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('Voter-card')
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			try:
				with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
					return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response
	return render(request,"sadmin/voter-id.html",locals())
	# qur_str = "SELECT * FROM webapp_service WHERE job == பான்;"

def ithura(request):
	qur_str = "SELECT * FROM webapp_service WHERE jobtit =='இதர' ;"	
	obj = Service.objects.raw(qur_str)[::-1] #show all records except last one in case show few add this [:n] where is number
	obj_lnk = ServiceLinks.objects.all()	
	is_ration_access = request.session.get("is_ration_access")
	is_aadhar_access = request.session.get("is_aadhar_access")
	is_pan_access = request.session.get("is_pan_access")
	is_welfare_access = request.session.get("is_welfare_access")
	is_ithara_access = request.session.get("is_ithara_access")
	is_voter_access = request.session.get("is_voter_access")
	is_view_only = request.session.get("is_view_only")	
	total_records = len(obj)
	if request.method == "POST":
		print("------------------------------",request.POST['form_name'])
		if request.POST['form_name'] == "newServiceFrom":
			print("1111111111111111111111111111111111111111111111111111111")
			try:
				job = request.POST['works']
			except:
				job = "Null"
			try:
				ondriyam = 	request.POST['taluk']
			except:
				ondriyam = "Null"
			try:
				oor =  request.POST['ஒன்றியம்']
			except:
				oor = "Null"
			try:
				oratchi = request.POST['ஊர் பெயர்கள்']
			except:
				oratchi = "Null"
			
		
			# 	 must required
			try:
				ondriyam = request.POST['taluk']
			except:
				messages.success(request,"---ஒன்றியம்--- உள்ளீடு நிரப்பப்பட வேண்டும் ")
				return redirect('sadmin-dashboard')
			try:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			except:
				Service(
				user = request.user,
				jobtit = request.POST['workTitle'],
				job = job,
				ithura = request.POST['ithura'],
				shopno = request.POST['kadaiNum'],
				refno = request.POST['NoteNum'],
				# refdoc = request.FILES['upData'],
				amount = request.POST['cash'],
				bname = request.POST['benName'],
				regmob = request.POST['RegConNum'],
				conmob = request.POST['conNum'],
				email = request.POST['benMail'],
				ondriyam = request.POST['taluk'],
				other = request.POST['others_1'],
				oor = oor,
				oratchi = oratchi,
				theru = request.POST['streeName'],
				date = datetime.datetime.now()
				
				).save()
			
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = job
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			print("1---55555555555555555555555555555555555555")
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, PASSWORD_RESET_TIMEOUT_DAYS_DEPRECATED_MSG)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				try:
					# return FileResponse(open("{}/certificate.pdf".format(BASE_DIR), 'rb'), content_type='application/pdf')
					with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
						return HttpResponse(f.read(), content_type="image/jpeg")
				except IOError:
					red = Image.new('RGBA', (1, 1), (255,0,0,0))
					response = HttpResponse(content_type="image/jpeg")
					red.save(response, "JPEG")
					return response	
									
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				return redirect('ithura')

		if request.POST['form_name'] == "identity":
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "subFilter2":
			print("22222222222222222222222222222222222222",request.POST['works2'])
			qur_str = "SELECT * FROM webapp_service WHERE job =='{}' ;".format(str(request.POST['works2']))
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "srhList":
			qur_str = "SELECT * FROM webapp_service WHERE '{}' in (jobno, jobtit, job, shopno, email, refno, bname, amount,regmob, conmob, ondriyam,oor,theru );".format(request.POST['searchList'])		
			obj = Service.objects.raw(qur_str)
			names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
			return render(request,"sadmin/view-all.html",locals())
		if request.POST['form_name'] == "edit":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.refno = request.POST['NoteNum']
			try:
				obj.refdoc = request.FILES['upData']
			except:pass
			obj.bname = request.POST['benName']
			obj.regmob = request.POST['RegConNum']
			obj.conmob = request.POST['conNum']
			obj.email = request.POST['benMail']
			#given key is not present in the POST then fallback with same 
			#value from service obj
			obj.job = request.POST.get('works', obj.job)	
			obj.jobtit = request.POST.get('workTitle',obj.jobtit)
			obj.shopno = request.POST.get('kadaiNum',obj.shopno)
			obj.amount = request.POST.get('cash',obj.amount)
			obj.ondriyam = request.POST.get('taluk',obj.ondriyam)
			obj.oor = request.POST.get('ஒன்றியம்',obj.oor)
			obj.oratchi = request.POST.get('ஊர் பெயர்கள்',obj.oratchi)
			obj.theru = request.POST.get('streeName',obj.theru)
			obj.status = request.POST.get('status',obj.status)
			obj.approve = request.POST.get('state',obj.approve)

			obj.save()
			messages.success(request,"Record Updated Successfully")
			return redirect('ration')		
		if request.POST['form_name'] == "del":
			obj = Service.objects.get(id = request.POST['idd'])
			obj.delete()
			messages.success(request,"Record Deleted Successfully")
			return redirect('ithura')		
		if request.POST['form_name'] == "CHECK":
			print("check form ---------------------------------------")
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			print(locals())
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			try:
				with open("{}/certif.jpg".format(BASE_DIR), "rb") as f:
					return HttpResponse(f.read(), content_type="image/jpeg")
			except IOError:
				red = Image.new('RGBA', (1, 1), (255,0,0,0))
				response = HttpResponse(content_type="image/jpeg")
				red.save(response, "JPEG")
				return response	
		if request.POST['form_name'] == "send_Certi":
			name = request.POST["benName"]
			refno = request.POST['NoteNum']
			jobtit = request.POST['workTitle']
			amount = request.POST['cash']
			date =  datetime.datetime.now()
			email = request.POST['benMail']
			try:
				user = AdminProfile.objects.get(user = request.user)
			except:None
			from pathlib import Path
			import os
			BASE_DIR = str(Path(__file__).resolve().parent.parent) + "/static/certificate"
			template = get_template("sadmin/cert.html")
			html  = template.render(locals())
			import subprocess
			# wkhtml2pdf = subprocess.Popen(("D:/wkhtmltopdf/bin/wkhtmltopdf.exe",
			wkhtml2pdf = subprocess.Popen(("wkhtmltopdf",
	                               "--print-media-type",
								   "--enable-local-file-access",
	                               "--encoding",
	                               "UTF-8",
	                               "-",
	                               "-"),
	                              stdin=subprocess.PIPE,
	                              stdout=subprocess.PIPE)
			wkdata = wkhtml2pdf.communicate(html.encode('utf8'))
			pdf = wkdata[0]
			
			data = open("{}/certificate.pdf".format(BASE_DIR),"wb")
			data.write(pdf)
			data.close()
						# //////////////////////////////////////////////////////
			pages = convert_from_path("{}/certificate.pdf".format(BASE_DIR), 500)
			for page in pages:
				page.save("{}/p_i.jpg".format(BASE_DIR), 'JPEG')
					
			print("1---2222222222222222222222222222222222222222222")
			# size is width/height
			img = Image.open("{}/p_i.jpg".format(BASE_DIR))
			print("1---33333333333333333333333333333333333333333")
			left = 10
			top = 1
			width = 4130
			height = 2620
			box = (left, top,width,height)
			area = img.crop(box)
			# croped completed
			print("1---44444444444444444444444444444444444444")
			# resize
			newsize = (793, 5593)
			area.resize(newsize, Image.ANTIALIAS)
			area.save("{}/certif.jpg".format(BASE_DIR), 'jpeg')
			area.close()
			# ====================================================================
			try:
				toaddr = email
				msg = MIMEMultipart() 
				msg['From'] = fromaddr 
				msg['To'] = toaddr
				msg['Subject'] = "நாம் தமிழர் கட்சி - இராவணன் மக்கள் சேவை மையம்"
				body = """ உங்களது {} கோரிக்கை நாம் தமிழர் கட்சி, வீரபாண்டி சட்டமன்ற தொகுதி, இராவணன் மக்கள் சேவை மையம், மூலமாக வெற்றிகரமாக பதிவு செய்யப்பட்டது.\n\nஉங்களது கோரிக்கை எண் :{}""".format(jobtit,refno)
				msg.attach(MIMEText(body, 'plain'))
				filename = "{}/certif.jpg".format(BASE_DIR)
				attachment = open(filename, "rb")
				p = MIMEBase('application', 'octet-stream')
				p.set_payload((attachment).read())
				encoders.encode_base64(p)
				p.add_header('Content-Disposition', "attachment; filename=cert.jpg")
				msg.attach(p)
				s = smtplib.SMTP('smtp.gmail.com', 587)
				s.starttls()
				s.login(fromaddr, password)
				text = msg.as_string()
				s.sendmail(fromaddr, toaddr, text)
				s.quit()
				# messages.success(request,"சேவை வெற்றிகரமாக பதிவு செய்யப்பட்டது")
				obj = obj
				print("222222222222222222222222222222222222222222222222222222")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
			except Exception as e:
				print("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", e)
				obj = obj
				messages.success(request,"மின்னஞ்சல் அனுப்ப முடியவில்லை")
				# return render(request,"sadmin/ration.html",locals())
				return redirect('ration')
		if request.POST['form_name'] == "DownCSV":
			output = []
			response = HttpResponse (content_type='text/csv')
			response['Content-Disposition'] = 'attachment; filename="{}-{}.csv"'.format("ration",f"{datetime.datetime.now():%Y-%m-%d-%H:-%M:%S}")
			writer = csv.writer(response)
			query_set = Service.objects.raw(qur_str)
			titles = ["user","வேலைகள் தலைப்பு","வேலைகள்","இதர","கடை எண்","குறிப்பு எண்","தொகை","பயனாளி பெயர்","பதிவு செய்யப்பட்ட கைபேசி","தொடர்பு எண்","பயனாளியின் மின்னஞ்சல்","ஒன்றியம் / பேரூராட்சி","other","ஊர் பெயர்கள்","ஊராட்சி","தெரு பெயர்கள்","status","date","approve"]
			writer.writerow(titles)
			for obj in query_set:	
				output.append([str(AdminProfile.objects.get(user = request.user)),obj.jobtit,obj.job,obj.ithura,obj.shopno,obj.refno,obj.amount,obj.bname,obj.bname,obj.conmob,obj.email,obj.ondriyam,obj.other,obj.oor,obj.oratchi,obj.theru,obj.status,obj.date,obj.approve,])
			writer.writerows(output)
			return response
	
	return render(request,"sadmin/others.html",locals())
	# qur_str = "SELECT * FROM webapp_service WHERE job == பான்;"

def downCert(request):
	return render(request,"sadmin/cert.html",locals())

def view_all(request):
	if request.POST['form_name'] == "subFilter2":
	# 	obj = Service.objects.raw(qur_str)
	# 	names = {"names":["புதிய மின்னணு குடும்ப அட்டை விண்ணப்ப", "நகல் மின்னணு குடும்ப அட்டை விண்ணப்ப", "குடும்ப அட்டையில் குடும்ப தலைவர் மாற்றம்", "குடும்ப‌ உறுப்பினர் சேர்க்கை", "குடும்ப உறுப்பினர் நீக்கம்", "குடும்ப அட்டை முகவரி மாற்றம்", "குடும்ப அட்டையில் கைபேசி எண் இணைக்க"]}
	# 	return render(request,"sadmin/view-all.html",locals())

		return HttpResponse(request,"<h1>Hello</h1>")

def index(request):
	indPage = IndexPage.objects.all()
	print("-----------------------------",indPage)	
	return render(request, "sadmin/index.html",locals())

def admin_das(request):
	indPage = IndexPage.objects.filter(id=1)
	try:
		ob = indPage[0]
	except TypeError:
		ob = None
		
	serLink = ServiceLinks.objects.all()

	lob = serLink[0]
	# print("---------------------------------------------------------> dsda",serLink.ration_1_title)
	# print("---------------------------------------------------------> len",len(lob))
	print("---------------------------------------------------------> list",dir(lob))
	# print("---------------------------------------------------------> list",request.POST)
	A_user = request.user
	try:
		A_user = AdminProfile.objects.get(user = request.user)
	except:pass
	if request.user.adminprofile == A_user:
		if request.method == "POST":
			print("------------------------------",request.POST['form_name'])
			if request.POST['form_name'] == "IndaxPage":
				print("----------------in index page form ------------------------",ob)
				ob.title =  request.POST['title']
				ob.SubTitle =  request.POST['SubTitle']
				ob.smallTitle =  request.POST['smallTitle']
				ob.smallTitleSub =  request.POST['smallTitleSub']
				ob.smallTitle_content_1 =  request.POST['smallTitle_content_1']
				ob.smallTitle_content_2 =  request.POST['smallTitle_content_2']
				ob.smallTitle_2 =  request.POST['smallTitle_2']
				ob.smallTitleSub_2 =  request.POST['smallTitleSub_2']
				ob.smallTitle_content_1_2 =  request.POST['smallTitle_content_1_2']
				ob.smallTitle_content_2_2 =  request.POST['smallTitle_content_2_2']
				ob.smallTitle_3 =  request.POST['smallTitle_3']
				ob.smallTitleSub_3 =  request.POST['smallTitleSub_3']
				ob.smallTitle_content_1_3 =  request.POST['smallTitle_content_1_3']
				ob.smallTitle_content_2_3 =  request.POST['smallTitle_content_2_3']
				ob.vrt_block_1 =  request.POST['vrt_block_1']
				ob.vrt_block_1_content =  request.POST['vrt_block_1_content']
				ob.vrt_block_2 =  request.POST['vrt_block_2']
				ob.vrt_block_2_content =  request.POST['vrt_block_2_content']
				ob.vrt_block_3 =  request.POST['vrt_block_3']
				ob.vrt_block_3_content =  request.POST['vrt_block_3_content']
				ob.mid_content =  request.POST['mid_content']
				ob.mid_content_sub =  request.POST['mid_content_sub']
				ob.bottom_content =  request.POST['bottom_content']
				ob.addressTitle =  request.POST['addressTitle']
				ob.address_1 =  request.POST['address_1']
				ob.address_2 =  request.POST['address_2']
				ob.address_3 =  request.POST['address_3']
				ob.facebook =  request.POST['facebook']
				ob.youtube =  request.POST['youtube']
				ob.twitter =  request.POST['twitter']
				ob.whatsapp =  request.POST['whatsapp']
				try:
					ob.cover_1  = request.FILES['cover_1']
				except:pass
				try:
					ob.cover_2  = request.FILES['cover_2']
				except:pass
				try:
					ob.cover_3  = request.FILES['cover_3']
				except:pass
				try:
					ob.news_1  = request.FILES['news_1']
				except:pass
				try:
					ob.news_2  = request.FILES['news_2']
				except:pass
				try:
					ob.news_3  = request.FILES['news_3']
				except:pass



				

				lob.ration_1_title = request.POST['Ration_Title_1']
				lob.ration_1_titleLink = request.POST['Ration_link_1']
				
				lob.ration_2_title = request.POST['Ration_Title_2']
				lob.ration_2_titleLink = request.POST['Ration_link_2']
				
				lob.ration_3_title = request.POST['Ration_Title_3']
				lob.ration_3_titleLink = request.POST['Ration_link_3']
				
				lob.ration_4_title = request.POST['Ration_Title_4']
				lob.ration_4_titleLink = request.POST['Ration_link_4']
			#-------------------------------------------------------------------------
				lob.aadhar_1_title = request.POST['aadhar_Title_1']
				lob.aadhar_1_titleLink = request.POST['aadhar_link_1']
				
				lob.aadhar_2_title = request.POST['aadhar_Title_2']
				lob.aadhar_2_titleLink = request.POST['aadhar_link_2']
				
				lob.aadhar_3_title = request.POST['aadhar_Title_3']
				lob.aadhar_3_titleLink = request.POST['aadhar_link_3']
				
				lob.aadhar_4_title = request.POST['aadhar_Title_4']
				lob.aadhar_4_titleLink = request.POST['aadhar_link_4']
			#-------------------------------------------------------------------------
				lob.pan_1_title = request.POST['pan_Title_1']
				lob.pan_1_titleLink = request.POST['pan_link_1']
				
				lob.pan_2_title = request.POST['pan_Title_2']
				lob.pan_2_titleLink = request.POST['pan_link_2']
				
				lob.pan_3_title = request.POST['pan_Title_3']
				lob.pan_3_titleLink = request.POST['pan_link_3']
				
				lob.pan_4_title = request.POST['pan_Title_4']
				lob.pan_4_titleLink = request.POST['pan_link_4']
			#-------------------------------------------------------------------------
				lob.welfar_1_title = request.POST['welfar_Title_1']
				lob.welfar_1_titleLink = request.POST['welfar_link_1']
				
				lob.welfar_2_title = request.POST['welfar_Title_2']
				lob.welfar_2_titleLink = request.POST['welfar_link_2']
				
				lob.welfar_3_title = request.POST['welfar_Title_3']
				lob.welfar_3_titleLink = request.POST['welfar_link_3']
				
				lob.welfar_4_title = request.POST['welfar_Title_4']
				lob.welfar_4_titleLink = request.POST['welfar_link_4']
			#-------------------------------------------------------------------------  
				lob.voter_1_title = request.POST['voter_id_Title_1']
				lob.voter_1_titleLink = request.POST['voter_id_link_1']
				
				lob.voter_2_title = request.POST['voter_id_Title_2']
				lob.voter_2_titleLink = request.POST['voter_id_link_2']
				
				lob.voter_3_title = request.POST['voter_id_Title_3']
				lob.voter_3_titleLink = request.POST['voter_id_link_3']
				
				lob.voter_4_title = request.POST['voter_id_Title_4']
				lob.voter_4_titleLink = request.POST['voter_id_link_4']
			#-------------------------------------------------------------------------
				lob.other_1_title = request.POST['other_Title_1']
				lob.other_1_titleLink = request.POST['other_link_1']
				
				lob.other_2_title = request.POST['other_Title_2']
				lob.other_2_titleLink = request.POST['other_link_2']
				
				lob.other_3_title = request.POST['other_Title_3']
				lob.other_3_titleLink = request.POST['other_link_3']
				
				lob.other_4_title = request.POST['other_Title_4']
				lob.other_4_titleLink = request.POST['other_link_4']


				ob.save()
				lob.save()

	return render(request, "sadmin/admin_das.html",locals())
