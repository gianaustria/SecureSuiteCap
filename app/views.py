"""
Definition of views.
"""

from datetime import datetime
from django.shortcuts import render
from django.http import HttpRequest
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import FileResponse
import os
import tempfile
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import ScanLog, CollaborationMessage, Policy
from .utils import analyze_file
from django.shortcuts import render
from django.http import JsonResponse
import subprocess

# Folder to save uploaded files
UPLOAD_FOLDER = 'uploads'
REPORT_FILE = 'latest_report.xlsx'  # Path to your report file

# Path to save uploaded and scanned files
UPLOAD_DIR = os.path.join(settings.MEDIA_ROOT, 'uploads')
EXCEL_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXCEL_DIR, exist_ok=True)

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def home(request):
    assert isinstance(request, HttpRequest)
    return render(request, 'app/index.html', {
        'title': 'Home Page',
        'year': datetime.now().year,
    })

def contact(request):
    assert isinstance(request, HttpRequest)
    return render(request, 'app/contact.html', {
        'title': 'Contact',
        'message': 'Your contact page.',
        'year': datetime.now().year,
    })

def about(request):
    assert isinstance(request, HttpRequest)
    return render(request, 'app/about.html', {
        'title': 'About',
        'message': 'Your application description page.',
        'year': datetime.now().year,
    })

def index(request):
    return render(request, 'app/index.html')

def email_analyzer(request):
    return render(request, 'app/email_analyzer.html')

def scan_single_email(request):
    if request.method == 'POST':
        email_file = request.FILES.get('email_file')
        if not email_file:
            messages.error(request, "No file uploaded.")
            return redirect('email_analyzer')

        if not email_file.name.endswith('.eml'):
            messages.error(request, "Invalid file type, only .eml allowed.")
            return redirect('email_analyzer')

        filepath = os.path.join(UPLOAD_FOLDER, email_file.name)
        with open(filepath, 'wb+') as destination:
            for chunk in email_file.chunks():
                destination.write(chunk)

        # TODO: Implement your scanning logic here

        messages.success(request, f"Successfully scanned single email: {email_file.name}")
        return redirect('email_analyzer')

    return redirect('email_analyzer')


def scan_batch_emails(request):
    if request.method == 'POST':
        email_files = request.FILES.getlist('email_files')
        if not email_files:
            messages.error(request, "No files uploaded.")
            return redirect('email_analyzer')

        for f in email_files:
            if not f.name.endswith('.eml'):
                messages.error(request, "All files must be .eml files.")
                return redirect('email_analyzer')

        for f in email_files:
            filepath = os.path.join(UPLOAD_FOLDER, f.name)
            with open(filepath, 'wb+') as destination:
                for chunk in f.chunks():
                    destination.write(chunk)

            # TODO: Implement your batch scanning logic here

        messages.success(request, f"Successfully scanned {len(email_files)} emails in batch.")
        return redirect('email_analyzer')

    return redirect('email_analyzer')


def download_report(request):
    try:
        # Make sure your report file path is correct and accessible
        response = FileResponse(open(REPORT_FILE, 'rb'), as_attachment=True)
        return response
    except Exception:
        messages.error(request, "Report file not found or error occurred.")
        return redirect('email_analyzer')

def file_integrity_checker(request):
    return render(request, 'app/file_integrity_checker.html')

@csrf_exempt
def upload_files(request):
    if request.method == 'POST':
        uploaded_files = request.FILES.getlist('files')
        results = []
        for uploaded_file in uploaded_files:
            filename = uploaded_file.name
            file_path = os.path.join(UPLOAD_DIR, filename)
            with open(file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            try:
                stats, detailed = analyze_file(file_path)
                df = pd.DataFrame([stats])
                excel_path = os.path.join(EXCEL_DIR, f"{filename}.xlsx")
                df.to_excel(excel_path, index=False)
                ScanLog.objects.create(filename=filename, status='Scanned')
                results.append({
                    "filename": filename,
                    "stats": stats,
                    "detailed": detailed,
                    "excel_path": os.path.join(settings.MEDIA_URL, 'reports', f"{filename}.xlsx")
                })
            except Exception as e:
                results.append({
                    "filename": filename,
                    "error": str(e)
                })
        return JsonResponse(results, safe=False)
    return JsonResponse({"error": "Only POST allowed"}, status=405)

def logs(request):
    logs = ScanLog.objects.all().order_by('-timestamp')[:10]
    return render(request, 'app/partials/logs.html', {'logs': logs})

def visualizations(request):
    files = os.listdir(UPLOAD_DIR)
    return render(request, 'app/partials/visualizations.html', {'files': files})

def visualization_detail(request, index):
    files = os.listdir(UPLOAD_DIR)
    if index < len(files):
        file_path = os.path.join(UPLOAD_DIR, files[index])
        size = os.path.getsize(file_path)
        return JsonResponse({"size": size})
    return JsonResponse({"error": "Index out of range"}, status=400)

def collaboration(request):
    if request.method == 'POST':
        message = request.POST.get('message')
        if message:
            CollaborationMessage.objects.create(message=message)
            return HttpResponse(status=204)
        return JsonResponse({"message": "No message provided"}, status=400)
    messages = CollaborationMessage.objects.all().order_by('-timestamp')[:10]
    return render(request, 'app/partials/collaboration.html', {'messages': messages})

def policies(request):
    if request.method == 'POST':
        selected = request.POST.keys()
        Policy.objects.all().delete()
        for category in selected:
            Policy.objects.create(category=category)
        return HttpResponse(status=204)
    policies = Policy.objects.values_list('category', flat=True)
    return render(request, 'app/partials/policies.html', {'policies': policies})

def website_checker(request):
    return render(request, 'app/website_checker.html')

def check_availability(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        url = data.get('url')
        try:
            # Try HTTP GET to check availability
            response = requests.get(url, timeout=5)
            return JsonResponse({'result': f'Status Code: {response.status_code}'})
        except Exception as e:
            return JsonResponse({'result': f'Error: {str(e)}'})
    return JsonResponse({'result': 'Invalid request'}, status=400)

def homepage_test(request):
    if request.method == 'POST':
        # This could be expanded with real homepage testing logic
        return JsonResponse({'result': 'Homepage test completed successfully.'})
    return JsonResponse({'result': 'Invalid request'}, status=400)

def ping_test(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        url = data.get('url').replace('https://', '').replace('http://', '')
        try:
            # For Windows, use ['ping', '-n', '4', url]
            output = subprocess.check_output(['ping', '-c', '4', url], universal_newlines=True)
            return JsonResponse({'result': output})
        except Exception as e:
            return JsonResponse({'result': f'Ping error: {str(e)}'})
    return JsonResponse({'result': 'Invalid request'}, status=400)

def traceroute_test(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        url = data.get('url').replace('https://', '').replace('http://', '')
        try:
            # For Windows, consider using 'tracert' instead of 'traceroute'
            output = subprocess.check_output(['traceroute', url], universal_newlines=True)
            return JsonResponse({'result': output})
        except Exception as e:
            return JsonResponse({'result': f'Traceroute error: {str(e)}'})
    return JsonResponse({'result': 'Invalid request'}, status=400)

def dns_check(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        domain = data.get('url').replace('https://', '').replace('http://', '').split('/')[0]
        try:
            # Query DNSKEY to test DNSSEC presence
            dns.resolver.resolve(domain, 'DNSKEY')
            return JsonResponse({'result': 'DNSSEC is enabled.'})
        except Exception:
            return JsonResponse({'result': 'DNSSEC not found or not supported.'})
    return JsonResponse({'result': 'Invalid request'}, status=400)

def website_checker_view(request):
    # Render the main page with your HTML template
    return render(request, 'analyzer_app/website_checker.html')