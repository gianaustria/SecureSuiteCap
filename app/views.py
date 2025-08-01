
from datetime import datetime
from django.shortcuts import render, redirect
from django.http import HttpRequest, JsonResponse, HttpResponse, FileResponse
from django.contrib import messages
from django.conf import settings
from .models import ScanLog, CollaborationMessage, Policy
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
from email import message_from_bytes, policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import shutil
import platform

# Configuration
UPLOAD_DIR = os.path.join(settings.MEDIA_ROOT, 'Uploads')
REPORT_DIR = os.path.join(settings.MEDIA_ROOT, 'reports')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

API_KEY = "bdc0a7e18fc1e1c91bd9d46501c6fc575228f53938421b72b160fed17a2378a5"
KEYWORDS_FILE = os.path.join(settings.BASE_DIR, 'keywords.txt')

# EmailAnalyzer and related classes
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
                time.sleep(1)  # Avoid rate limits
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
                time.sleep(1)  # Avoid rate limits
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
            "Authentication-Results": auth_results,
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

    def save_results_to_file(self, filename="scan_results.txt"):
        filename = os.path.join(REPORT_DIR, filename)
        with open(filename, "w", encoding="utf-8") as f:
            f.write("From: " + self.header_analysis.get("From", "") + "\n")
            f.write("Reply-To: " + self.header_analysis.get("Reply-To", "") + "\n")
            f.write("Return-Path: " + self.header_analysis.get("Return-Path", "") + "\n")
            f.write("Authentication-Results: " + self.header_analysis.get("Authentication-Results", "") + "\n")
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
            if self.keywords_found.get("High Risk"):
                messages.warning(request, "This email contains high-risk keywords.")
                f.write("- This email contains high-risk keywords (e.g., 'order', 'document').\n")
                f.write("  ⚠️ Be cautious — do NOT click links or download attachments unless verified.\n")
            if self.keywords_found.get("Medium Risk"):
                messages.warning(request, "Medium-risk words found in email.")
                f.write("- Medium-risk words found (e.g., 'login', 'password').\n")
                f.write("  🕵️ Double-check the sender and go to official websites directly.\n")
            if self.keywords_found.get("Low Risk"):
                messages.info(request, "Low-risk marketing terms found in email.")
                f.write("- Low-risk marketing terms found (e.g., 'free', 'offer').\n")
                f.write("  🔍 Watch out for scams or clickbait. Avoid impulsive actions.\n")
            if self.malicious_links or self.malicious_attachments:
                messages.error(request, "Malicious content detected in email.")
                f.write("\n⚠️ Malicious content was detected. Follow these precautions:\n")
                f.write("1. 🚫 Don’t open suspicious links or attachments.\n")
                f.write("2. 🧠 If unsure, verify the sender by other means.\n")
                f.write("3. 🔐 Keep antivirus up-to-date.\n")
            if (
                not self.keywords_found.get("High Risk") and
                not self.keywords_found.get("Medium Risk") and
                not self.malicious_links and
                not self.malicious_attachments and
                not self.header_analysis.get("Flags")
            ):
                messages.success(request, "This email appears to be safe.")
                f.write("\n✅ This email appears to be safe.\n")
                f.write("No malicious links, attachments, or suspicious headers were detected.\n")
        return filename

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

# Utility function for URL cleaning
def clean_url(target):
    target = target.strip()
    if not target:
        return None, None
    target = re.sub(r'^www\.', '', target, flags=re.IGNORECASE)
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target
    domain = re.sub(r'^(http://|https://)', '', target).split('/')[0]
    return target, domain

# Utility function for file analysis (placeholder)
def analyze_file(file_path):
    stats = {'size': os.path.getsize(file_path), 'type': file_path.split('.')[-1]}
    detailed = f"Analyzed {file_path}"
    return stats, detailed

# Updated upload_files view with malware scanning
def upload_files(request):
    if request.method == 'POST':
        uploaded_files = request.FILES.getlist('files')
        results = []
        scanner = AttachmentScanner(API_KEY)
        for uploaded_file in uploaded_files:
            if not uploaded_file.name.endswith(('.exe', '.dll', '.pdf', '.txt', '.docx', '.eml')):
                results.append({'filename': uploaded_file.name, 'error': 'Unsupported file type'})
                continue

            safe_filename = re.sub(r'[^\w.-]', '_', uploaded_file.name)
            file_path = os.path.join(UPLOAD_DIR, safe_filename)
            try:
                # Save the file
                with open(file_path, 'wb+') as dest:
                    for chunk in uploaded_file.chunks():
                        dest.write(chunk)
                
                # Basic file analysis
                stats, detailed = analyze_file(file_path)
                
                # Malware scan
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

                # Generate Excel report
                df = pd.DataFrame([stats])
                excel_filename = f"{safe_filename}.xlsx"
                excel_path = os.path.join(REPORT_DIR, excel_filename)
                df.to_excel(excel_path, index=False)
                
                # Log to database
                ScanLog.objects.create(filename=uploaded_file.name, status='Scanned', stats=stats)
                results.append({
                    'filename': uploaded_file.name,
                    'stats': stats,
                    'detailed': detailed,
                    'excel_path': f"{settings.MEDIA_URL}reports/{excel_filename}"
                })
            except Exception as e:
                results.append({'filename': uploaded_file.name, 'error': str(e)})
        
        return JsonResponse(results, safe=False)
    return JsonResponse({"error": "Only POST allowed"}, status=405)

# Other views (unchanged)
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
            messages.error(request, "No file uploaded.")
            return redirect('email_analyzer')
        
        if not email_file.name.endswith('.eml'):
            messages.error(request, "Invalid file type, only .eml allowed.")
            return redirect('email_analyzer')

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
            
            ScanLog.objects.create(filename=email_file.name, status='Scanned', stats=stats)
            messages.success(request, "Done scanning. You may download the report below.")
            return redirect('email_analyzer')
        except Exception as e:
            messages.error(request, f"Error scanning email: {str(e)}")
            return redirect('email_analyzer')
    
    return redirect('email_analyzer')

def scan_batch_emails(request):
    if request.method == 'POST':
        email_files = request.FILES.getlist('email_files')
        if not email_files:
            messages.error(request, "No files uploaded.")
            return redirect('email_analyzer')

        report = ""
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
                
                with open(temp_report_path, 'r', encoding='utf-8') as f:
                    report += f"Results for {email_file.name}:\n{f.read()}\n{'=' * 80}\n"
                
                ScanLog.objects.create(filename=email_file.name, status='Scanned', stats=stats)
            except Exception as e:
                messages.error(request, f"Error scanning email {email_file.name}: {str(e)}")
        
        report_path = os.path.join(REPORT_DIR, 'scan_results.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        messages.success(request, "Batch scan complete. You may download the report below.")
        return redirect('email_analyzer')
    
    return redirect('email_analyzer')

def download_report(request):
    report_path = os.path.join(REPORT_DIR, 'scan_results.txt')
    try:
        return FileResponse(open(report_path, 'rb'), as_attachment=True, filename='scan_results.txt')
    except Exception as e:
        messages.error(request, f"Error downloading report: {str(e)}")
        return redirect('email_analyzer')

def file_integrity_checker(request):
    return render(request, 'app/file_integrity_checker.html')

def logs(request):
    try:
        logs = ScanLog.objects.all().order_by('-timestamp')[:10]
        return render(request, 'app/partials/logs.html', {'logs': logs})
    except Exception as e:
        print(f"Error in logs view: {str(e)}")
        return HttpResponse(f"Error: {str(e)}", status=500)

def visualizations(request):
    files = os.listdir(UPLOAD_DIR)
    return render(request, 'app/partials/visualizations.html', {'files': files})

def visualization_detail(request, index):
    files = os.listdir(UPLOAD_DIR)
    if index < len(files):
        file_path = os.path.join(UPLOAD_DIR, files[index])
        size = os.path.getsize(file_path)
        stats = {'size': size, 'type': files[index].split('.')[-1]}
        return JsonResponse({"stats": stats})
    return JsonResponse({"error": "Index out of range"}, status=400)

def collaboration(request):
    if request.method == 'POST':
        message = request.POST.get('message')
        if message and len(message) >= 10:
            CollaborationMessage.objects.create(message=message)
            return HttpResponse(status=204)
        return JsonResponse({"message": "Message too short or not provided"}, status=400)
    messages = CollaborationMessage.objects.all().order_by('-timestamp')[:10]
    return render(request, 'app/partials/collaboration.html', {'messages': messages})

def policies(request):
    if request.method == 'POST':
        selected = request.POST.keys()
        Policy.objects.all().delete()
        for category in ['Malicious', 'Suspicious', 'Harmless']:
            if category in selected:
                Policy.objects.create(category=category)
        return HttpResponse(status=204)
    policies = Policy.objects.values_list('category', flat=True)
    return render(request, 'app/partials/policies.html', {'policies': policies})

def website_checker(request):
    return render(request, 'app/website_checker.html')

def check_availability(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            web = data.get('url')
            if not web:
                return JsonResponse({"result": "Error: No URL provided"}, status=400)
            
            web, domain = clean_url(web)
            if not web or not domain:
                return JsonResponse({"result": "Error: Invalid URL format"}, status=400)
            
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return JsonResponse({"result": f"Error: Could not resolve hostname {domain}"}, status=400)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
            try:
                response = requests.head(web, timeout=5, allow_redirects=True, headers=headers)
                if response.status_code in [405, 403]:
                    response = requests.get(web, timeout=5, allow_redirects=True, headers=headers)
                status_text = f"Status: {response.status_code} ({'Available' if response.status_code == 200 else 'Not Available'})"
                return JsonResponse({"result": status_text})
            except requests.exceptions.RequestException as e:
                return JsonResponse({"result": f"Error: Invalid URL or Unreachable - {str(e)}"}, status=400)
        except Exception as e:
            return JsonResponse({"result": f"Error: Unexpected issue - {str(e)}"}, status=500)
    return JsonResponse({"result": "Invalid request"}, status=400)

def homepage_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            target = data.get('url')
            target, domain = clean_url(target)
            if not target or not domain:
                return JsonResponse({"result": "Error: Invalid URL format"}, status=400)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = urllib.request.Request(target, headers=headers)
            with urllib.request.urlopen(response, timeout=10) as resp:
                status_code = resp.getcode()
                content_length = resp.getheader('Content-Length', 'Unknown')
                server = resp.getheader('Server', 'Unknown')
                ip = socket.gethostbyname(domain)
                result_text_content = (
                    f"Homepage Test Results:\n"
                    f"Status: {'Available' if status_code == 200 else 'Not Available'} (Code: {status_code})\n"
                    f"IP Address: {ip}\n"
                    f"Server: {server}\n"
                    f"Content Length: {content_length} bytes"
                )
            return JsonResponse({"result": result_text_content})
        except Exception as e:
            return JsonResponse({"result": f"Homepage Test Failed: Invalid URL or Unreachable - {str(e)}"}, status=400)
    return JsonResponse({"result": "Invalid request"}, status=400)

def ping_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            domain = clean_url(data.get('url'))[1]
            if not domain:
                return JsonResponse({"result": "Error: Invalid URL format"}, status=400)
            
            ip = socket.gethostbyname(domain)
            ping_cmd = ["ping", "-n" if platform.system() == 'Windows' else "-c", "4", domain]
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                formatted_output = f"PING {domain} ({ip}) 56(84) bytes of data.\n"
                response_count = 0
                for line in output_lines:
                    if response_count < 4:
                        match = re.search(r'(\d+) bytes from ([\w.-]+) \(([\d.]+)\): icmp_seq=(\d+) ttl=(\d+) time=([\d.]+) ms', line)
                        if match:
                            bytes_sent, hostname, ip_addr, seq, ttl, time = match.groups()
                            formatted_output += f"{bytes_sent} bytes from {hostname} ({ip_addr}): icmp_seq={seq} ttl={ttl} time={time} ms\n"
                            response_count += 1
                stats_match = re.search(r'(\d+) packets transmitted, (\d+) received, (\d+)% packet loss(?:, time (\d+)ms)?', result.stdout)
                if stats_match:
                    transmitted, received, loss, *time_parts = stats_match.groups()
                    total_time = time_parts[0] if time_parts and time_parts[0] else "N/A"
                    formatted_output += f"\n--- {domain} ping statistics ---\n"
                    formatted_output += f"{transmitted} packets transmitted, {received} received, {loss}% packet loss, time {total_time}ms\n"
                return JsonResponse({"result": formatted_output})
            else:
                return JsonResponse({"result": f"Ping Failed: Host {domain} is unreachable or invalid\n{result.stderr.strip()}"})
        except socket.gaierror as e:
            return JsonResponse({"result": f"Ping Failed: Could not resolve hostname {domain} - {str(e)}"})
        except subprocess.TimeoutExpired:
            return JsonResponse({"result": f"Ping Timed Out while pinging {domain}"})
        except Exception as e:
            return JsonResponse({"result": f"Ping Failed: Error - {str(e)}"})
    return JsonResponse({"result": "Invalid request"}, status=400)

def traceroute_test(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            domain = clean_url(data.get('url'))[1]
            if not domain:
                return JsonResponse({"result": "Error: Invalid URL format"}, status=400)
            
            ip = socket.gethostbyname(domain)
            trace_cmd = ["tracert", "-d", domain] if platform.system() == 'Windows' else ["traceroute", "-n", domain]
            result = subprocess.run(trace_cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                formatted_output = f"Traceroute to {domain} ({ip}):\n"
                for i, line in enumerate(lines[:5]):
                    formatted_output += line + "\n"
                return JsonResponse({"result": formatted_output})
            else:
                return JsonResponse({"result": f"Traceroute Failed:\n{result.stderr.strip()}"})
        except socket.gaierror:
            return JsonResponse({"result": f"Traceroute Error: Could not resolve hostname {domain}"})
        except subprocess.TimeoutExpired:
            return JsonResponse({"result": f"Traceroute Timed Out for {domain}"})
        except Exception as e:
            return JsonResponse({"result": f"Traceroute Error: {str(e)}"})
    return JsonResponse({"result": "Invalid request"}, status=400)

def dns_check(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            domain = clean_url(data.get('url'))[1]
            if not domain:
                return JsonResponse({"result": "Error: Invalid URL format"}, status=400)
            
            security_info = f"DNS Security Check for {domain}:\n"
            resolver = dns.resolver.Resolver()
            try:
                spf_records = resolver.resolve(domain, 'TXT')
                spf_found = False
                for record in spf_records:
                    if "spf" in record.strings[0].decode().lower():
                        security_info += f"- SPF Record: Found\n  Value: {record.strings[0].decode()}\n"
                        spf_found = True
                        break
                if not spf_found:
                    security_info += "- SPF Record: Not Found (Potential email spoofing risk)\n"
            except dns.resolver.NoAnswer:
                security_info += "- SPF Record: Not Found\n"
            except dns.resolver.NXDOMAIN:
                security_info += "- SPF Record: Not Found (Domain does not exist)\n"
            
            try:
                dmarc_records = resolver.resolve('_dmarc.' + domain, 'TXT')
                dmarc_found = False
                for record in dmarc_records:
                    if "dmarc" in record.strings[0].decode().lower():
                        security_info += f"- DMARC Record: Found\n  Value: {record.strings[0].decode()}\n"
                        dmarc_found = True
                        break
                if not dmarc_found:
                    security_info += "- DMARC Record: Not Found (Increased risk of email spoofing)\n"
            except dns.resolver.NoAnswer:
                security_info += "- DMARC Record: Not Found\n"
            except dns.resolver.NXDOMAIN:
                security_info += "- DMARC Record: Not Found (Domain does not exist)\n"
            
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                security_info += "\nNS Records:\n" + "\n".join([str(r) for r in answers])
            except dns.resolver.NXDOMAIN:
                security_info += "\nNS Records: Not Found (Domain does not exist)\n"
            
            return JsonResponse({"result": security_info})
        except Exception as e:
            return JsonResponse({"result": f"Error during DNS Security Check: {str(e)}"})
    return JsonResponse({"result": "Invalid request"}, status=400)

def login(request):
    return render(request, 'app/login.html', {
        'title': 'Login',
        'year': datetime.now().year,
    })