"""esevai URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

admin.site.site_header = " Ravanan E-Sevai Admin"
admin.site.site_title = " Ravanan E-Sevai Admin Portal"
admin.site.index_title = "Welcome to Ravanan E-Sevai Admin Portal"

from webapp import users as u
from webapp import sadmin as s
urlpatterns = [
    path('admin/', admin.site.urls),

    # User Dashboard
    path('user/dashboard/', u.dash, name = "user-dashboard"),
    path('user/profile/', u.profile, name = "user-profile"),
    path('user/service/history/', u.service_history, name = "user-service-history"),
    path('user/register/', u.Register, name = "user-register"),
    path('user/login/', u.Login, name = "user-login"),
    path('user/logout/', u.Logout, name = "user-logout"),
    path('user/ForgotPassword/', u.forgotpass, name = "user-forgotpass"),
    path('user/VerifyCode/<str:mobile>/', u.verify_otp, name = "user-verify-otp"),
    path('user/LoginVerifyCode/<str:mobile>/', u.verify_otp_login, name = "user-verify-otp-login"),
    path('user-password-change/',u.PasswordChangeView.as_view(template_name='user/password_change_form.html'),name='user-password-change-form'),
    path('user-password-change-done/', u.PasswordChangeDoneView.as_view(template_name='user/password_change_done.html'), name='user-password-change-done'),

    # SuperAdmin Dashboard
    path('', s.index, name = "index"),
    path('sadmin-dashboard', s.dash, name = "sadmin-dashboard"),
    path('sadmin/service/getmore/', s.getmore, name = "sadmin-getmore"),
    path('sadmin/register/', s.Register, name = "sadmin-register"),
    path('sadmin/login/', s.Login, name = "sadmin-login"),
    path('sadmin/logout/', s.Logout, name = "sadmin-logout"),
    path('sadmin/ForgotPassword/', s.forgotpass, name = "sadmin-forgotpass"),
    path('sadmin/VerifyCode/<str:mobile>/', s.verify_otp, name = "sadmin-verify-otp"),
    path('sadmin/LoginVerifyCode/<str:mobile>/', s.verify_otp_login, name = "sadmin-verify-otp-login"),
    path('sadmin-password-change/',s.PasswordChangeView.as_view(template_name='sadmin/password_change_form.html'),name='sadmin-password-change-form'),
    path('sadmin-password-change-done/', s.PasswordChangeDoneView.as_view(template_name='sadmin/password_change_done.html'), name='sadmin-password-change-done'),
    path('sadmin/service/downloadCsv/', s.downCsv, name = "download-csv"),
    path('sadmin/service/downloadCert/', s.downCert, name = "download-cer"),
    # path('sadmin/service/ration/', s.downCsv, name = "download-csv"),
    path('sadmin/service/ration', s.r_card, name = "ration"),

    path('sadmin/service/aadhar', s.aadhar, name = "aadhar"),
    path('sadmin/service/pan', s.pan, name = "pan"),
    path('sadmin/service/welfare', s.welfar, name = "Welfare"),
    path('sadmin/service/voter-id', s.voter_id, name = "Voter-card"),
    path('sadmin/service/others', s.ithura, name = "ithura"),

    path('sadmin/service/view-all/', s.view_all, name = "view-all"),

    path('sadmin/dash/', s.admin_das, name = "dash"),


]
urlpatterns += staticfiles_urlpatterns()
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
