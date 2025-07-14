from django.urls import path
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from app import forms, views
from datetime import datetime

urlpatterns = [
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('login/',
         LoginView.as_view(
             template_name='app/login.html',
             authentication_form=forms.BootstrapAuthenticationForm,
             extra_context={'title': 'Log in', 'year': datetime.now().year}
         ),
         name='login'),
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('admin/', admin.site.urls),
    path('email-analyzer/', views.email_analyzer, name='email_analyzer'),
    path('file-integrity-checker/', views.file_integrity_checker, name='file_integrity_checker'),
    path('website-checker/', views.website_checker, name='website_checker'),
    path('scan/', views.scan_single_email, name='scan_single_email'),
    path('batch/', views.scan_batch_emails, name='scan_batch_emails'),
    path('download/', views.download_report, name='download_report'),
    path('file-integrity-checker/', views.file_integrity_checker, name='file_integrity_checker'),
    path('upload-files/', views.upload_files, name='upload_files'),
    path('logs/', views.logs, name='logs'),
    path('visualizations/', views.visualizations, name='visualizations'),
    path('visualization/<int:index>/', views.visualization_detail, name='visualization_detail'),
    path('collaboration/', views.collaboration, name='collaboration'),
    path('policies/', views.policies, name='policies'),
    path('website-checker/', views.website_checker_view, name='website_checker'),
    path('website-checker/check', views.check_availability, name='check_availability'),
    path('website-checker/homepage', views.homepage_test, name='homepage_test'),
    path('website-checker/ping', views.ping_test, name='ping_test'),
    path('website-checker/traceroute', views.traceroute_test, name='traceroute_test'),
    path('website-checker/dns', views.dns_check, name='dns_check'),
]