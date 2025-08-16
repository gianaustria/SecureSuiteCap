import os
import tempfile
import pandas as pd
import requests
import socket
import subprocess
import re
import dns.resolver
import urllib.request
import json
import hashlib
import threading
import time
import csv
import logging
from email import message_from_bytes, policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import shutil
import platform
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib import messages
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from .models import ScanLog, CollaborationMessage, Policy
from django.utils.datastructures import MultiValueDictKeyError
from django.db import transaction, models
from .models import ScanLog
from io import StringIO
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .forms import SignUpForm
from django.contrib.auth import login
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User

# Set up logging at the top of the file
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Output to console
    ]
)
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_DIR = os.path.join(settings.MEDIA_ROOT, 'Uploads')
REPORT_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

API_KEY = "bdc0a7e18fc1e1c91bd9d46501c6fc575228f53938421b72b160fed17a2378a5"
KEYWORDS_FILE = os.path.join(settings.BASE_DIR, 'keywords.txt')

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            auth_login(request, user)  # auto login after signup
            return redirect('home')  # redirect to your homepage or dashboard
    else:
        form = SignUpForm()

    return render(request, 'app/signup.html', {'form': form})

def logout_view(request):
    if request.user.is_authenticated:
        logger.debug(f"User {request.user.username} logged out")
        logout(request)
    return redirect('home')  # Redirect to home page after logout

def login_view(request):
    if request.user.is_authenticated:
        return redirect('account')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                request.session['_auth_user_login_time'] = datetime.now().isoformat()
                request.session.modified = True
                logger.debug(f"User {username} logged in successfully")
                return redirect('account')
            else:
                logger.warning(f"Authentication failed for username: {username}")
                form.add_error(None, "Invalid username or password")
        else:
            logger.warning("Invalid form submission for login")
    else:
        form = AuthenticationForm()
    
    return render(request, 'app/login.html', {'form': form, 'title': 'Log in'})

@login_required
def account_view(request):
    session = request.session
    session_key = session.session_key
    session_expiry = session.get_expiry_date() if session_key else None
    context = {
        'title': 'Account',
        'username': request.user.username,
        'email': request.user.email,
        'date_joined': request.user.date_joined,
        'session_key': session_key or 'Not available',
        'session_expiry': session_expiry,
        'login_time': session.get('_auth_user_login_time', None),
    }
    return render(request, 'app/account.html', context)

def profile_view(request, username):
    user_obj = get_object_or_404(User, username=username)

    # Attempt to get session info if request.user matches user_obj
    session = request.session if request.user == user_obj else None

    context = {
        'title': f"{user_obj.username}'s Account",
        'username': user_obj.username,
        'email': user_obj.email,
        'date_joined': user_obj.date_joined,
        'session_key': session.session_key if session else 'N/A',
        'login_time': session.get('_session_init_time', 'Not available') if session else 'Not available',
        'session_expiry': session.get_expiry_date() if session else None,
    }

    return render(request, 'app/account.html', context)

# EmailAnalyzer and related classes (unchanged for brevity)
class KeywordDetector:
    def __init__(self, keywords_file):
        self.keywords = self.load_keywords(keywords_file)

    def load_keywords(self, keywords_file):
        keywords = {'High Risk': [], 'Medium Risk': [], 'Low Risk': []}
        current_category = None
        with open(keywords_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_category = line[1:-1]
                elif current_category and line:
                    keywords[current_category].append(line.lower())
        return keywords

    def detect(self, text):
        found_keywords = {'High Risk': [], 'Medium Risk': [], 'Low Risk': []}
        threads = []
        def scan_category(category, words):
            for word in words:
                if word in text.lower():
                    found_keywords[category].append(word)
        for category, words in self.keywords.items():
            t = threading.Thread(target=scan_category, args=(category, words))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return found_keywords

class LinkScanner:
    def __init__(self, api_key):
        self.api_key = api_key

    def scan(self, links):
        if not links:
            return {}, "None"
        malicious_links = {}
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        url = "https://www.virustotal.com/api/v3/urls"
        for link in links:
            try:
                time.sleep(1)
                response = requests.post(url, headers=headers, data={"url": link})
                if response.status_code == 200:
                    scan_id = response.json().get("data", {}).get("id", "")
                    if scan_id:
                        count = self.check_url_scan_results(scan_id)
                        if count > 0:
                            malicious_links[link] = count
            except:
                continue
        return malicious_links, ""

    def check_url_scan_results(self, scan_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        headers = {"x-apikey": self.api_key}
        for _ in range(5):
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json().get("data", {})
                if data.get("attributes", {}).get("status") == "completed":
                    return data.get("attributes", {}).get("stats", {}).get("malicious", 0)
                time.sleep(10)
        return 0

class AttachmentScanner:
    def __init__(self, api_key):
        self.api_key = api_key

    def scan(self, attachments):
        if not attachments:
            return {}, "None"
        malicious_attachments = {}
        headers = {"x-apikey": self.api_key}
        for filepath in attachments:
            if not os.path.exists(filepath) or os.path.getsize(filepath) > 32 * 1024 * 1024:
                continue
            try:
                time.sleep(1)
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    malicious_count = data.get("last_analysis_stats", {}).get("malicious", 0)
                    if malicious_count > 0:
                        malicious_attachments[os.path.basename(filepath)] = {
                            "malicious_count": malicious_count,
                            "analysis_results": data.get("last_analysis_results", {})
                        }
            except:
                continue
        return malicious_attachments, "None" if not malicious_attachments else f"{len(malicious_attachments)} files flagged"

class EmailAnalyzer:
    def __init__(self, api_key, keywords_file):
        self.api_key = api_key
        self.keywords_file = keywords_file
        self.links = []
        self.attachments = []
        self.email_body = ""
        self.keywords_found = {}
        self.malicious_links = {}
        self.malicious_attachments = {}
        self.header_analysis = {}
        self.recommendations = []
        self.attachment_dir = os.path.join(settings.MEDIA_ROOT, "attachments")
        if os.path.exists(self.attachment_dir):
            shutil.rmtree(self.attachment_dir)
        os.makedirs(self.attachment_dir, exist_ok=True)
    
    def scan_headers(self, email_message):
        headers = dict(email_message.items())
        from_header = headers.get("From", "Missing")
        reply_to = headers.get("Reply-To", "Missing")
        return_path = headers.get("Return-Path", "Missing")
        auth_results = headers.get("Authentication-Results", "Not found")
        flags = []
        if return_path != "Missing" and return_path != from_header:
            flags.append("⚠️ From and Return-Path mismatch")
        if reply_to != "Missing" and reply_to != from_header:
            flags.append("⚠️ Reply-To differs from From")
        if "spf=fail" in auth_results.lower():
            flags.append("❌ SPF failed")
        if "dkim=fail" in auth_results.lower():
            flags.append("❌ DKIM failed")
        if "dmarc=fail" in auth_results.lower():
            flags.append("❌ DMARC failed")
        self.header_analysis = {
            "From": from_header,
            "Reply-To": reply_to,
            "Return-Path": return_path,
            "Authentication_Results": auth_results,
            "Flags": flags
        }
    
    def get_email_body(self, email_message):
        body = ""
        for part in email_message.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body += part.get_payload(decode=True).decode(errors="ignore") + "\n"
                except:
                    continue
        return body

    def analyze_email(self, email_file):
        with open(email_file, 'rb') as f:
            email_message = BytesParser(policy=policy.default).parse(f)
        self.scan_headers(email_message)
        self.email_body = self.get_email_body(email_message)
        link_thread = threading.Thread(target=self._extract_links_thread)
        attachment_thread = threading.Thread(target=self.extract_attachments, args=(email_message,))
        link_thread.start()
        attachment_thread.start()
        link_thread.join()
        attachment_thread.join()
        self.keywords_found = KeywordDetector(self.keywords_file).detect(self.email_body)
        self.malicious_links, _ = LinkScanner(self.api_key).scan(self.links)
        self.malicious_attachments, _ = AttachmentScanner(self.api_key).scan(self.attachments)
        
        if self.keywords_found.get("High Risk"):
            self.recommendations.append("This email contains high-risk keywords (e.g., 'order', 'document'). Be cautious — do NOT click links or download attachments unless verified.")
        if self.keywords_found.get("Medium Risk"):
            self.recommendations.append("Medium-risk words found (e.g., 'login', 'password'). Double-check the sender and go to official websites directly.")
        if self.keywords_found.get("Low Risk"):
            self.recommendations.append("Low-risk marketing terms found (e.g., 'free', 'offer'). Watch out for scams or clickbait. Avoid impulsive actions.")
        if self.malicious_links or self.malicious_attachments:
            self.recommendations.extend([
                "Malicious content detected. Follow these precautions:",
                "1. 🚫 Don’t open suspicious links or attachments.",
                "2. 🧠 If unsure, verify the sender by other means.",
                "3. 🔐 Keep antivirus up-to-date."
            ])
        if (
            not self.keywords_found.get("High Risk") and
            not self.keywords_found.get("Medium Risk") and
            not self.malicious_links and
            not self.malicious_attachments and
            not self.header_analysis.get("Flags")
        ):
            self.recommendations.append("This email appears to be safe. No malicious links, attachments, or suspicious headers were detected.")

    def save_results_to_file(self, filename="scan_results.txt"):
        filename = os.path.join(REPORT_DIR, filename)
        with open(filename, "w", encoding="utf-8") as f:
            f.write("From: " + self.header_analysis.get("From", "") + "\n")
            f.write("Reply-To: " + self.header_analysis.get("Reply-To", "") + "\n")
            f.write("Return-Path: " + self.header_analysis.get("Return-Path", "") + "\n")
            f.write("Authentication-Results: " + self.header_analysis.get("Authentication_Results", "") + "\n")
            f.write("Header Flags: \n")
            for flag in self.header_analysis.get("Flags", []):
                f.write("- " + flag + "\n")
            f.write("\nSafe Links:\n")
            for link in self.links:
                if link not in self.malicious_links:
                    f.write("[✔] " + link + "\n")
            f.write("\nMalicious Links:\n")
            for link, count in self.malicious_links.items():
                f.write(f"[⚠️] {link} - flagged by {count} vendors\n")
            f.write("\nSafe Attachments:\n")
            for att in self.attachments:
                if os.path.basename(att) not in self.malicious_attachments:
                    f.write("[✔] " + os.path.basename(att) + "\n")
            f.write("\nMalicious Attachments:\n")
            for att, count in self.malicious_attachments.items():
                f.write(f"[⚠️] {att} - flagged by {count['malicious_count']} vendors\n")
            f.write("\nKeywords Found:\n")
            for level, words in self.keywords_found.items():
                f.write(f"{level}: {', '.join(words) if words else 'None'}\n")
            f.write("\nSecurity Recommendations:\n")
            for rec in self.recommendations:
                f.write(f"- {rec}\n")
        return filename

    def get_results(self, filename):
        return {
            'filename': filename,
            'headers': {
                'From': self.header_analysis.get('From', 'N/A'),
                'To': self.header_analysis.get('To', 'N/A'),
                'Subject': self.header_analysis.get('Subject', 'N/A')
            },
            'header_analysis': self.header_analysis,
            'safe_links': [link for link in self.links if link not in self.malicious_links],
            'malicious_links': self.malicious_links,
            'safe_attachments': [os.path.basename(att) for att in self.attachments if os.path.basename(att) not in self.malicious_attachments],
            'malicious_attachments': self.malicious_attachments,
            'keywords_found': self.keywords_found,
            'recommendations': self.recommendations
        }

    def _extract_links_thread(self):
        self.links = self.extract_links(self.email_body)

    @staticmethod
    def is_valid_url(url):
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https'] or not parsed.netloc or "%00" in url:
            return False
        try:
            parsed.netloc.encode('ascii')
        except UnicodeEncodeError:
            return False
        return True

    @classmethod
    def extract_links(cls, email_body):
        soup = BeautifulSoup(email_body, "html.parser")
        href_links = [a.get('href') for a in soup.find_all('a', href=True)]
        inline_links = [a.get_text() for a in soup.find_all('a') if a.get_text().startswith("http")]
        text_links = re.findall(r'https?://[^\s\'"<>]+(?=[\s\'"<>,]|$)', soup.get_text())
        raw_links = href_links + inline_links + text_links
        return [link for link in set(raw_links) if cls.is_valid_url(link)]

    def extract_attachments(self, email_message):
        for part in email_message.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    filename = os.path.basename(filename.replace('\x00', ''))
                    filepath = os.path.join(self.attachment_dir, filename)
                    with open(filepath, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                    self.attachments.append(filepath)

# Utility functions
def clean_url(target):
    target = target.strip()
    if not target:
        return None, None
    target = re.sub(r'^www\.', '', target, flags=re.IGNORECASE)
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target
    domain = re.sub(r'[](http://|https://)', '', target).split('/')[0]
    return target, domain

def analyze_file(file_path):
    stats = {'size': os.path.getsize(file_path), 'type': file_path.split('.')[-1].lower()}
    scanner = AttachmentScanner(API_KEY)
    scan_results, scan_summary = scanner.scan([file_path])
    filename = os.path.basename(file_path)
    if filename in scan_results:
        stats['malware_status'] = f"Malicious: flagged by {scan_results[filename]['malicious_count']} vendors"
        stats['malware_details'] = {
            vendor: result for vendor, result in scan_results[filename]['analysis_results'].items() if result['category'] == 'malicious'
        }
    else:
        stats['malware_status'] = "No malicious content detected"
        stats['malware_details'] = {}
    detailed = f"Analyzed {filename}: {stats['malware_status']}"
    return stats, detailed

# Views
def file_integrity_checker(request):
    if request.user.is_authenticated:
        logs = ScanLog.objects.filter(user=request.user)
    else:
        session_key = request.session.session_key
        if not session_key:
            request.session.create()
            session_key = request.session.session_key
        logs = ScanLog.objects.filter(session_key=session_key, user__isnull=True)

    malicious_count = 0
    non_malicious_count = 0
    for log in logs:
        try:
            stats = json.loads(log.stats) if isinstance(log.stats, str) else log.stats
            if stats.get('malware_status', '').startswith('Malicious'):
                malicious_count += 1
            else:
                non_malicious_count += 1
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing stats for ScanLog ID={log.id}: {str(e)}")
            continue

    policies = {
        'categories': ['Malware', 'Phishing', 'Suspicious'],
        'extensions': '.exe,.dll,.pdf,.txt,.docx,.eml',
        'keywords': 'malware, virus, trojan'
    }
    messages = [
        {'id': 1, 'message': 'Sample message', 'timestamp': '2025-08-06 19:00:00'}
    ]

    context = {
        'logs': logs,
        'malicious_count': malicious_count,
        'non_malicious_count': non_malicious_count,
        'policies': policies,
        'messages': messages
    }
    return render(request, 'app/file_integrity_checker.html', context)

def get_logs(request):
    if request.user.is_authenticated:
        logs = ScanLog.objects.filter(user=request.user)
    else:
        session_key = request.session.session_key
        if not session_key:
            request.session.save()
            session_key = request.session.session_key
        logs = ScanLog.objects.filter(session_key=session_key)

    logs = logs.order_by('-created_at')
    logs_data = []

    for log in logs:
        try:
            stats = json.loads(log.stats) if isinstance(log.stats, str) else log.stats
            stats.setdefault('size', 'Unknown')
            stats.setdefault('type', 'Unknown')
            stats.setdefault('malware_status', 'Unknown')
            stats.setdefault('malware_details', {})
        except json.JSONDecodeError as e:
            print(f"Error parsing stats for ScanLog ID={log.id}: {str(e)}")
            stats = {'size': 'Unknown', 'type': 'Unknown', 'malware_status': 'Unknown', 'malware_details': {}}

        logs_data.append({
            'filename': log.filename,
            'status': log.status,
            'stats': stats,
            'created_at': log.created_at.isoformat(),
            'user__username': log.user.username if log.user else "Anonymous"
        })

    return JsonResponse({'logs': logs_data}, safe=False)

def get_collaboration(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        messages = CollaborationMessage.objects.all().order_by('-timestamp').values('id', 'message', 'timestamp')
        messages = [
            {
                'id': msg['id'],
                'message': msg['message'],
                'timestamp': msg['timestamp'].isoformat()
            }
            for msg in messages
        ]
        return JsonResponse({'messages': messages})
    return JsonResponse({'error': 'Invalid request'}, status=400)

def get_policies(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        policies = {
            'categories': list(Policy.objects.values_list('category', flat=True)),
            'extensions': Policy.objects.first().extensions if Policy.objects.exists() else '.exe,.dll,.pdf,.txt,.docx,.eml',
            'keywords': '\n'.join(['order', 'document', 'urgent', 'login', 'password', 'account', 'free', 'offer', 'discount'])
        }
        try:
            with open(KEYWORDS_FILE, 'r') as f:
                policies['keywords'] = f.read()
        except:
            pass
        return JsonResponse({'policies': policies})
    return JsonResponse({'error': 'Invalid request'}, status=400)

def upload_files(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    uploaded_files = request.FILES.getlist('files')
    results = []
    scanner = AttachmentScanner(API_KEY)
    
    # Ensure session_key exists for unauthenticated users
    session_key = request.session.session_key
    if not request.session.session_key:
        request.session.save()  # ensures session exists
        session_key = request.session.session_key


    for uploaded_file in uploaded_files:
        if not uploaded_file.name.endswith(('.exe', '.dll', '.pdf', '.txt', '.docx', '.eml')):
            results.append({'filename': uploaded_file.name, 'error': 'Unsupported file type'})
            continue

        safe_filename = re.sub(r'[^\w.-]', '_', uploaded_file.name)
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        try:
            with open(file_path, 'wb+') as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)
            
            stats, detailed = analyze_file(file_path)
            stats = stats or {}
            stats.setdefault('size', 0)
            stats.setdefault('type', uploaded_file.name.split('.')[-1].lower())
            scan_results, scan_summary = scanner.scan([file_path])
            malware_info = scan_results.get(safe_filename, None)
            if malware_info:
                stats['malware_status'] = f"Malicious: flagged by {malware_info['malicious_count']} vendors"
                stats['malware_details'] = {
                    vendor: result for vendor, result in malware_info['analysis_results'].items() if result['category'] == 'malicious'
                }
            else:
                stats['malware_status'] = "No malicious content detected"
                stats['malware_details'] = {}

            df = pd.DataFrame([stats])
            excel_filename = f"{safe_filename}.xlsx"
            excel_path = os.path.join(REPORT_DIR, excel_filename)
            df.to_excel(excel_path, index=False)
            
            try:
                with transaction.atomic():
                    stats_serialized = json.dumps(stats) if isinstance(ScanLog._meta.get_field('stats'), models.TextField) else stats
                    scan_log = ScanLog.objects.create(
                        filename=uploaded_file.name,
                        status='Scanned',
                        stats=stats_serialized,
                        user=request.user if request.user.is_authenticated else None,
                        session_key=session_key if not request.user.is_authenticated else None
                    )
                    user_str = request.user.username if request.user.is_authenticated else 'Anonymous'
                    logger.debug(f"Saved ScanLog: ID={scan_log.id}, Filename={scan_log.filename}, User={user_str}")
            except Exception as db_error:
                logger.error(f"Error saving to ScanLog for {uploaded_file.name}: {str(db_error)}")
                results.append({'filename': uploaded_file.name, 'error': f"Database error: {str(db_error)}"})
                continue

            results.append({
                'filename': uploaded_file.name,
                'stats': stats,
                'detailed': detailed,
                'excel_path': f"{settings.MEDIA_URL}reports/{excel_filename}"
            })
        except Exception as e:
            logger.error(f"Error processing {uploaded_file.name}: {str(e)}")
            results.append({'filename': uploaded_file.name, 'error': str(e)})
    
    logger.debug(f"Upload results: {results}")
    return JsonResponse({'success': True, 'results': results}, safe=False)

@csrf_exempt
def edit_message(request, message_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            message = get_object_or_404(CollaborationMessage, id=message_id)
            message.message = data.get('message', message.message)
            message.timestamp = datetime.now()
            message.save()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request'})

def delete_message(request, message_id):
    if request.method == 'POST':
        try:
            message = get_object_or_404(CollaborationMessage, id=message_id)
            message.delete()
            messages.success(request, "Message deleted.")
            return redirect('file_integrity_checker')
        except Exception as e:
            messages.error(request, f"Error deleting message: {str(e)}")
    return redirect('file_integrity_checker')

def policies(request):
    if request.method == 'POST':
        categories = request.POST.getlist('categories')
        extensions = request.POST.get('extensions', '.exe,.dll,.pdf,.txt,.docx,.eml')
        keywords = request.POST.get('keywords', '')
        Policy.objects.all().delete()
        for category in categories:
            Policy.objects.create(category=category, extensions=extensions)
        with open(KEYWORDS_FILE, 'w') as f:
            f.write(keywords)
        messages.success(request, "Policies updated.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True})
        return redirect('file_integrity_checker')
    return redirect('file_integrity_checker')

def home(request):
    return render(request, 'app/index.html', {
        'title': 'Home Page',
        'year': datetime.now().year,
    })

def contact(request):
    if request.method == 'POST':
        messages.success(request, "Message sent successfully!")
        return redirect('contact')
    return render(request, 'app/contact.html', {
        'title': 'Contact',
        'message': 'Your contact page.',
        'year': datetime.now().year,
    })

def about(request):
    return render(request, 'app/about.html', {
        'title': 'About',
        'message': 'Your application description page.',
        'year': datetime.now().year,
    })



def email_analyzer(request):
    return render(request, 'app/email_analyzer.html')

def scan_single_email(request):
    if request.method == 'POST':
        email_file = request.FILES.get('email_file')
        if not email_file:
            return render(request, 'app/email_scan_results.html', {
                'error': "No file uploaded."
            })
        
        if not email_file.name.endswith('.eml'):
            return render(request, 'app/email_scan_results.html', {
                'error': "Invalid file type, only .eml allowed."
            })

        try:
            email_content = email_file.read()
            email = message_from_bytes(email_content)
            headers = {
                'From': email.get('From', 'N/A'),
                'To': email.get('To', 'N/A'),
                'Subject': email.get('Subject', 'N/A')
            }
            stats = {'size': len(email_content), 'type': 'eml'}

            temp_dir = tempfile.mkdtemp()
            filepath = os.path.join(temp_dir, email_file.name)
            with open(filepath, 'wb') as f:
                f.write(email_content)

            messages.info(request, f"[?] Scanning single file: {email_file.name}")
            analyzer = EmailAnalyzer(API_KEY, KEYWORDS_FILE)
            analyzer.analyze_email(filepath)
            analyzer.save_results_to_file("scan_results.txt")
            
            results = analyzer.get_results(email_file.name)
            ScanLog.objects.create(filename=email_file.name, status='Scanned', stats=stats)
            messages.success(request, "Email scan completed.")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True, 'results': [results]})
            return render(request, 'app/email_scan_results.html', {
                'results': [results]
            })
        except Exception as e:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': f"Error scanning email: {str(e)}"})
            return render(request, 'app/email_scan_results.html', {
                'error': f"Error scanning email: {str(e)}"
            })
    
    return redirect('email_analyzer')

def scan_batch_emails(request):
    if request.method == 'POST':
        email_files = request.FILES.getlist('email_files')
        if not email_files:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': "No files uploaded."})
            return render(request, 'app/email_scan_results.html', {
                'error': "No files uploaded."
            })

        results = []
        for email_file in email_files:
            if not email_file.name.endswith('.eml'):
                messages.error(request, f"Invalid file type: {email_file.name}")
                continue

            try:
                email_content = email_file.read()
                email = message_from_bytes(email_content)
                headers = {
                    'From': email.get('From', 'N/A'),
                    'To': email.get('To', 'N/A'),
                    'Subject': email.get('Subject', 'N/A')
                }
                stats = {'size': len(email_content), 'type': 'eml'}

                temp_dir = tempfile.mkdtemp()
                filepath = os.path.join(temp_dir, email_file.name)
                with open(filepath, 'wb') as f:
                    f.write(email_content)

                messages.info(request, f"[?] Scanning: {email_file.name}")
                analyzer = EmailAnalyzer(API_KEY, KEYWORDS_FILE)
                analyzer.analyze_email(filepath)
                
                temp_report_path = os.path.join(temp_dir, 'temp_result.txt')
                analyzer.save_results_to_file(temp_report_path)
                
                ScanLog.objects.create(filename=email_file.name, status='Scanned', stats=stats)
                results.append(analyzer.get_results(email_file.name))
            except Exception as e:
                messages.error(request, f"Error scanning email {email_file.name}: {str(e)}")
        
        report_path = os.path.join(REPORT_DIR, 'scan_results.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"Results for {result['filename']}:\n")
                f.write("From: " + result['header_analysis'].get("From", "") + "\n")
                f.write("Reply-To: " + result['header_analysis'].get("Reply-To", "") + "\n")
                f.write("Return-Path: " + result['header_analysis'].get("Return-Path", "") + "\n")
                f.write("Authentication-Results: " + result['header_analysis'].get("Authentication_Results", "") + "\n")
                f.write("Header Flags: \n")
                for flag in result['header_analysis'].get("Flags", []):
                    f.write("- " + flag + "\n")
                f.write("\nSafe Links:\n")
                for link in result['safe_links']:
                    f.write("[✔] " + link + "\n")
                f.write("\nMalicious Links:\n")
                for link, count in result['malicious_links'].items():
                    f.write(f"[⚠️] {link} - flagged by {count} vendors\n")
                f.write("\nSafe Attachments:\n")
                for att in result['safe_attachments']:
                    f.write("[✔] " + att + "\n")
                f.write("\nMalicious Attachments:\n")
                for att, count in result['malicious_attachments'].items():
                    f.write(f"[⚠️] {att} - flagged by {count['malicious_count']} vendors\n")
                f.write("\nKeywords Found:\n")
                for level, words in result['keywords_found'].items():
                    f.write(f"{level}: {', '.join(words) if words else 'None'}\n")
                f.write("\nSecurity Recommendations:\n")
                for rec in result['recommendations']:
                    f.write(f"- {rec}\n")
                f.write("\n" + "=" * 80 + "\n")
        
        messages.success(request, "Batch scan complete.")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'results': results})
        return render(request, 'app/email_scan_results.html', {
            'results': results
        })
    
    return redirect('email_analyzer')

def download_report(request):
    report_path = os.path.join(REPORT_DIR, 'scan_results.txt')
    try:
        return FileResponse(open(report_path, 'rb'), as_attachment=True, filename='scan_results.txt')
    except Exception as e:
        messages.error(request, f"Error downloading report: {str(e)}")
        return redirect('email_analyzer')

def website_checker(request):
    return render(request, 'app/website_checker.html')

URL_REGEX = r'^(https?://)?([\w-]+\.)*[\w-]+\.[a-zA-Z]{2,}(/.*)?$'

def clean_url(url):
    if not url.startswith("http"):
        url = "http://" + url
    domain = url.split("//")[-1].split("/")[0]
    return url, domain

def check_availability(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url')
            if not url:
                return JsonResponse({"result": "Error: No URL provided"}, status=400)

            full_url, domain = clean_url(url)

            # Verify domain resolves
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return JsonResponse({"result": f"Error: Could not resolve hostname {domain}"}, status=400)

            # Make GET request with timeout and simple user-agent
            headers = {'User-Agent': 'Mozilla/5.0'}
            try:
                response = requests.get(full_url, headers=headers, timeout=5)
                status = response.status_code
                if status == 200:
                    message = f"Website is available (Status Code: {status})"
                else:
                    message = f"Website returned status code {status}"
                return JsonResponse({"result": message})
            except requests.exceptions.RequestException as e:
                return JsonResponse({"result": f"Error: Unable to reach website - {str(e)}"}, status=400)
        except Exception as e:
            return JsonResponse({"result": f"Unexpected error: {str(e)}"}, status=500)

    return JsonResponse({"result": "Invalid request"}, status=400)

def homepage_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            target, domain = clean_url(data.get('url'))
            headers = {
                'User-Agent': 'Mozilla/5.0'
            }
            import urllib.request
            req = urllib.request.Request(target, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.getcode()
                content_length = resp.getheader('Content-Length', 'Unknown')
                server = resp.getheader('Server', 'Unknown')
                ip = socket.gethostbyname(domain)
                result_text = (
                    f"Homepage Test Results:\n"
                    f"Status: {'Available' if status_code == 200 else 'Not Available'} (Code: {status_code})\n"
                    f"IP Address: {ip}\n"
                    f"Server: {server}\n"
                    f"Content Length: {content_length} bytes"
                )
            return JsonResponse({"result": result_text})
        except Exception as e:
            return JsonResponse({"result": f"Homepage Test Failed: {str(e)}"}, status=400)
    return JsonResponse({"result": "Invalid request"}, status=400)

def ping_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            _, domain = clean_url(data.get('url'))
            ip = socket.gethostbyname(domain)
            cmd = ["ping", "-n" if platform.system() == 'Windows' else "-c", "4", domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if proc.returncode == 0:
                return JsonResponse({"result": proc.stdout})
            else:
                return JsonResponse({"result": f"Ping failed:\n{proc.stderr}"})
        except Exception as e:
            return JsonResponse({"result": f"Ping test error: {str(e)}"}, status=400)
    return JsonResponse({"result": "Invalid request"}, status=400)

def traceroute_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            _, domain = clean_url(data.get('url'))
            cmd = ["tracert", "-d", domain] if platform.system() == 'Windows' else ["traceroute", "-n", domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                return JsonResponse({"result": proc.stdout})
            else:
                return JsonResponse({"result": f"Traceroute failed:\n{proc.stderr}"})
        except Exception as e:
            return JsonResponse({"result": f"Traceroute test error: {str(e)}"}, status=400)
    return JsonResponse({"result": "Invalid request"}, status=400)

def dns_check(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            _, domain = clean_url(data.get('url'))
            resolver = dns.resolver.Resolver()

            spf_txt = "SPF record not found"
            try:
                answers = resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = rdata.strings[0].decode()
                    if "spf" in txt.lower():
                        spf_txt = f"SPF record found: {txt}"
                        break
            except Exception:
                pass

            dmarc_txt = "DMARC record not found"
            try:
                answers = resolver.resolve('_dmarc.' + domain, 'TXT')
                for rdata in answers:
                    txt = rdata.strings[0].decode()
                    if "dmarc" in txt.lower():
                        dmarc_txt = f"DMARC record found: {txt}"
                        break
            except Exception:
                pass

            ns_txt = ""
            try:
                answers = resolver.resolve(domain, 'NS')
                ns_txt = "NS records:\n" + "\n".join(str(r) for r in answers)
            except Exception:
                ns_txt = "No NS records found"

            result = f"DNS Security Check for {domain}:\n{spf_txt}\n{dmarc_txt}\n{ns_txt}"
            return JsonResponse({"result": result})
        except Exception as e:
            return JsonResponse({"result": f"DNS check error: {str(e)}"}, status=400)
    return JsonResponse({"result": "Invalid request"}, status=400)

def download_logs(request):
    try:
        logger.debug("Starting download_logs view")
        if request.user.is_authenticated:
            logs = ScanLog.objects.filter(user=request.user)
        else:
            session_key = request.session.session_key
            if not session_key:
                request.session.create()
                session_key = request.session.session_key
            logs = ScanLog.objects.filter(session_key=session_key, user__isnull=True)
        
        logger.debug(f"Retrieved {logs.count()} logs for user {request.user.username if request.user.is_authenticated else 'Anonymous'}")
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Filename', 'Status', 'Size', 'Type', 'Malware Status', 'Malware Details', 'Created At', 'User'])
        
        for log in logs:
            try:
                stats = json.loads(log.stats) if isinstance(log.stats, str) else log.stats
                malware_details = json.dumps(stats.get('malware_details', {}))
                user_str = log.user.username if log.user else 'Anonymous'
                writer.writerow([
                    log.filename,
                    log.status,
                    stats.get('size', 'Unknown'),
                    stats.get('type', 'Unknown'),
                    stats.get('malware_status', 'Unknown'),
                    malware_details,
                    log.created_at.isoformat(),
                    user_str
                ])
                logger.debug(f"Processed log for {log.filename}")
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing stats for ScanLog ID={log.id}: {str(e)}")
                writer.writerow([
                    log.filename,
                    log.status,
                    'Unknown',
                    'Unknown',
                    'Unknown',
                    '{}',
                    log.created_at.isoformat(),
                    log.user.username if log.user else 'Anonymous'
                ])
            except Exception as e:
                logger.error(f"Unexpected error processing log ID={log.id}: {str(e)}")
                continue
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="scan_logs.csv"'
        response.write(output.getvalue())
        output.close()
        logger.debug("CSV generated and response prepared")
        return response
    except Exception as e:
        logger.error(f"Error in download_logs: {str(e)}")
        return JsonResponse({'error': f"Failed to download logs: {str(e)}"}, status=500)

def download_website_results(request):
    if request.method != 'POST':
        return HttpResponse('Only POST allowed', status=405)
    
    try:
        logger.debug("Starting download_website_results view")
        data = json.loads(request.body)
        logger.debug(f"Received data: {data}")
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['URL', 'Availability', 'Homepage Test', 'Ping Test', 'Traceroute Test', 'DNS Check'])
        writer.writerow([
            data.get('url', 'N/A'),
            data.get('availability', 'N/A'),
            data.get('homepage', 'N/A'),
            data.get('ping', 'N/A'),
            data.get('traceroute', 'N/A'),
            data.get('dns', 'N/A')
        ])
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="website_results_{data.get("url", "results").replace("/", "_")}_{datetime.now().strftime("%Y-%m-%d")}.csv"'
        response.write(output.getvalue())
        output.close()
        logger.debug("Website results CSV generated and response prepared")
        return response
    except Exception as e:
        logger.error(f"Error in download_website_results: {str(e)}")
        return HttpResponse(f'Error: {str(e)}', status=500)

def collaboration(request):
    if request.method == 'POST':
        message = request.POST.get('message')
        if message:
            CollaborationMessage.objects.create(message=message, timestamp=datetime.now())
            messages.success(request, "Message posted.")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
        else:
            messages.error(request, "Message cannot be empty.")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'Message cannot be empty.'})
    return redirect('file_integrity_checker')