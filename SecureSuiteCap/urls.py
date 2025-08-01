
from django.urls import path
from app import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView

urlpatterns = [
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('login/', views.login, name='login'),  # Added login URL
    path('email-analyzer/', views.email_analyzer, name='email_analyzer'),
    path('scan-single/', views.scan_single_email, name='scan_single_email'),
    path('scan-batch/', views.scan_batch_emails, name='scan_batch_emails'),
    path('download/', views.download_report, name='download_report'),
    path('file-integrity-checker/', views.file_integrity_checker, name='file_integrity_checker'),
    path('upload/', views.upload_files, name='upload_files'),
    path('logs/', views.logs, name='logs'),
    path('visualizations/', views.visualizations, name='visualizations'),
    path('visualization/<int:index>/', views.visualization_detail, name='visualization_detail'),
    path('collaboration/', views.collaboration, name='collaboration'),
    path('policies/', views.policies, name='policies'),
    path('website-checker/', views.website_checker, name='website_checker'),
    path('check/', views.check_availability, name='check_availability'),
    path('homepage/', views.homepage_test, name='homepage_test'),
    path('ping/', views.ping_test, name='ping_test'),
    path('traceroute/', views.traceroute_test, name='traceroute_test'),
    path('dns/', views.dns_check, name='dns_check'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)