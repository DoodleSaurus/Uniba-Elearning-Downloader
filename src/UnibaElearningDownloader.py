import requests
import json
import os.path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import threading
import queue
from urllib.parse import unquote, urljoin
from bs4 import BeautifulSoup
import re
import hashlib
import tkinter.font as tkfont
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from collections import defaultdict

# Credentials
USERNAME = ""
PASSWORD = ""
ORGANIZATION = "studenti-uniba"


class Course:
    def __init__(self, title, link):
        self.title = title
        self.link = link
        self.file_count = 0
        self.downloaded_count = 0

class DownloadManager:
    def __init__(self, progress_callback=None, file_count_callback=None):
        self.session = None
        self.downloaded_files = {}
        self.file_list_name = "fileslist.json"
        self.log_queue = queue.Queue()
        self.is_running = False
        self.progress_callback = progress_callback
        self.file_count_callback = file_count_callback
        self.course_stats = {}
        
        # Headers
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        
        self.headers2 = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9,ja-JP;q=0.8,ja;q=0.7",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "idpuniba.uniba.it",
            "Origin": "https://idpuniba.uniba.it",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            "sec-ch-ua": """Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141""",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
        }

    def sanitize_filename(self, filename):
        # Remove invalid characters from filename
        return re.sub(r'[<>:"/\\|?*]', '_', filename)

    def safe_find_text(self, text, start_marker, end_marker=None):
        # Safely extract text between markers
        try:
            start_idx = text.index(start_marker)
            if end_marker:
                end_idx = text.index(end_marker, start_idx + len(start_marker))
                return text[start_idx + len(start_marker):end_idx]
            else:
                return text[start_idx + len(start_marker):]
        except ValueError:
            return None

    def log(self, message, level="INFO"):
        # Add message to log queue with timestamp and level
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put(f"[{timestamp}] [{level}] {message}")

    def update_progress(self, value, max_value=None):
        # Update progress bar
        if self.progress_callback:
            self.progress_callback(value, max_value)

    def update_file_counts(self, course_name, total_files, downloaded_files):
        # Update file counts for a course
        if self.file_count_callback:
            self.file_count_callback(course_name, total_files, downloaded_files)

    def load_downloaded_files(self):
        # Load the list of already downloaded files
        if not os.path.exists(self.file_list_name):
            with open(self.file_list_name, "w", encoding='utf-8') as f:
                f.write("{}")
        
        try:
            with open(self.file_list_name, "r", encoding='utf-8') as f:
                self.downloaded_files = json.load(f)
        except (json.JSONDecodeError, Exception):
            self.downloaded_files = {}

    def save_downloaded_files(self):
        # Save the list of downloaded files
        try:
            with open(self.file_list_name, "w", encoding='utf-8') as outfile:
                json.dump(self.downloaded_files, outfile, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log(f"Error saving file list: {e}", "ERROR")

    def login(self, username, password, organization):
        # Perform login procedure
        try:
            self.session = requests.Session()
            
            # Get login page
            self.log("Connecting to elearning platform...", "INFO")
            self.update_progress(5)
            req = self.session.get("https://elearning.uniba.it/login/index.php", 
                                 headers=self.headers, timeout=30)
            req.raise_for_status()

            # Find IDP URL using BeautifulSoup
            soup = BeautifulSoup(req.text, 'html.parser')
            idp_div = soup.find('div', class_='login-identityproviders')
            if not idp_div:
                self.log("Error: IDP section not found", "ERROR")
                return False

            idp_link = idp_div.find('a')
            if not idp_link or 'href' not in idp_link.attrs:
                self.log("Error: IDP link not found", "ERROR")
                return False

            idp_url = idp_link['href']
            self.log(f"Found IDP URL: {idp_url}", "INFO")

            # Get IDP cookies
            self.log("Getting IDP session...", "INFO")
            self.update_progress(15)
            edp_req = self.session.get(idp_url, allow_redirects=True, timeout=30)
            edp_req.raise_for_status()

            # Login
            self.log("Logging in...", "INFO")
            login_params = {
                "username": username,
                "password": password,
                "organization": organization
            }

            login_req = self.session.post(edp_req.url, data=login_params, 
                                        headers=self.headers2, allow_redirects=False, timeout=30)

            if '<div class="message-box error">' in login_req.text:
                self.log("Error: Invalid credentials", "ERROR")
                return False

            # Handle consent and SAML
            if login_req.status_code == 303:
                self.update_progress(25)
                return self.handle_saml_redirect(login_req.headers["Location"])
            else:
                self.log("Unexpected login response", "ERROR")
                return False

        except requests.RequestException as e:
            self.log(f"Network error: {e}", "ERROR")
            return False
        except Exception as e:
            self.log(f"Unexpected error during login: {e}", "ERROR")
            return False

    def handle_saml_redirect(self, location):
        # Handle SAML redirect and consent
        try:
            # Get consent page
            consent_req = self.session.get(location, headers=self.headers2, timeout=30)
            consent_req.raise_for_status()

            # Confirm consent
            consent_url = consent_req.url + "&yes="
            confirm_req = self.session.get(consent_url, headers=self.headers2, 
                                         allow_redirects=True, timeout=30)
            confirm_req.raise_for_status()

            # Extract SAML data safely
            saml_response = self.safe_find_text(confirm_req.text, 
                                              'name="SAMLResponse" value="', '"')
            relay_state = self.safe_find_text(confirm_req.text, 
                                            'name="RelayState" value="', '"')
            
            if not saml_response or not relay_state:
                self.log("Error: SAML data not found", "ERROR")
                return False

            relay_state = relay_state.replace("&amp;amp;", "&")

            # Final redirect
            redirect_url = "https://elearning.uniba.it/auth/saml2/sp/saml2-acs.php/elearning.uniba.it"
            redirect_data = {
                "SAMLResponse": saml_response,
                "RelayState": relay_state
            }
            
            redirect_req = self.session.post(redirect_url, data=redirect_data, 
                                           headers=self.headers, allow_redirects=True, timeout=30)
            redirect_req.raise_for_status()

            # Check if login successful
            if "MDL_SSP_AuthToken" not in self.session.cookies:
                self.log("Error: Authentication failed", "ERROR")
                return False

            # Get username
            soup = BeautifulSoup(redirect_req.text, 'html.parser')
            user_span = soup.find('span', class_='usertext')
            if user_span:
                username = user_span.get_text(strip=True)
                self.log(f"Welcome, {username}!", "SUCCESS")
            else:
                self.log("Login successful!", "SUCCESS")

            self.update_progress(35)
            return True

        except requests.RequestException as e:
            self.log(f"Network error during SAML: {e}", "ERROR")
            return False
        except Exception as e:
            self.log(f"Error during SAML handling: {e}", "ERROR")
            return False

    def get_courses(self):
        # Get list of available courses
        try:
            self.log("Fetching courses...", "INFO")
            self.update_progress(45)
            courses_req = self.session.get("https://elearning.uniba.it/my/courses.php", 
                                         headers=self.headers, timeout=30)
            courses_req.raise_for_status()

            soup = BeautifulSoup(courses_req.text, 'html.parser')
            courses = []
            
            # Find course links in the sidebar
            aside = soup.find('aside', id='block-region-side-post')
            if aside:
                course_links = aside.find_all('a', tabindex='-1')
                for link in course_links:
                    title = link.get('title', '').strip()
                    href = link.get('href', '').strip()
                    
                    if title and href and title not in ["Forum", "Elearning UniBA"]:
                        course = Course(title, href)
                        courses.append(course)
                        self.course_stats[title] = {"total": 0, "downloaded": 0}
                        self.log(f"Found course: {title}", "INFO")

            return courses

        except Exception as e:
            self.log(f"Error fetching courses: {e}", "ERROR")
            return []

    def scan_course_files(self, course):
        # Scan course to count total files
        try:
            # Get course page
            course_page = self.session.get(course.link, headers=self.headers, timeout=30)
            course_page.raise_for_status()
            
            soup = BeautifulSoup(course_page.text, 'html.parser')
            
            # Count file resources
            file_activities = soup.find_all('div', class_='activityname')
            file_count = 0
            
            for activity in file_activities:
                if activity.find('span', class_='accesshide', string='File') or activity.find('span', class_='accesshide'):
                    # Find the link
                    link = activity.find('a')
                    if link and 'href' in link.attrs:
                        file_count += 1
            
            course.file_count = file_count
            safe_course_name = self.sanitize_filename(course.title)
            
            # Count already downloaded files for this course
            downloaded_count = 0
            if safe_course_name in self.downloaded_files:
                downloaded_count = len(self.downloaded_files[safe_course_name])
            
            course.downloaded_count = downloaded_count
            self.course_stats[course.title] = {"total": file_count, "downloaded": downloaded_count}
            
            self.log(f"Course '{course.title}': {file_count} files found, {downloaded_count} already downloaded", "INFO")
            
            return file_count
            
        except Exception as e:
            self.log(f"Error scanning course {course.title}: {e}", "ERROR")
            return 0

    def download_course_files(self, courses):
        # Download files from courses
        total_new_files = 0
        total_files_to_process = 0
        
        # First, scan all courses to get total file count
        self.log("Scanning courses for files...", "INFO")
        for course in courses:
            total_files = self.scan_course_files(course)
            total_files_to_process += total_files
        
        self.log(f"Total files to process: {total_files_to_process}", "INFO")
        self.update_progress(50, total_files_to_process)
        
        processed_files = 0
        
        for course_idx, course in enumerate(courses):
            course_new_files = 0
            
            # Create course directory
            safe_course_name = self.sanitize_filename(course.title)
            if not os.path.exists(safe_course_name):
                os.makedirs(safe_course_name, exist_ok=True)

            if safe_course_name not in self.downloaded_files:
                self.downloaded_files[safe_course_name] = []

            self.log(f"\nProcessing course: {course.title} ({course_idx + 1}/{len(courses)})", "INFO")
            
            try:
                # Get course page
                course_page = self.session.get(course.link, headers=self.headers, timeout=30)
                course_page.raise_for_status()
                
                soup = BeautifulSoup(course_page.text, 'html.parser')
                
                # Find file resources
                file_activities = soup.find_all('div', class_='activityname')
                
                for activity_idx, activity in enumerate(file_activities):
                    if activity.find('span', class_='accesshide', string='File') or activity.find('span', class_='accesshide'):
                        # Find the link
                        link = activity.find('a')
                        if link and 'href' in link.attrs:
                            file_page_url = urljoin(course.link, link['href'])
                            # Resolve actual file URL (pluginfile.php or direct)
                            download_url = self.resolve_file_url(file_page_url)
                            
                            # Extract file ID from URL or generate a hash fallback
                            file_id = None
                            if 'id=' in download_url:
                                file_id = download_url.split('id=')[1].split('&')[0]
                            
                            title = link.get_text(strip=True) or os.path.basename(download_url)
                            
                            # fallback id if none
                            if not file_id:
                                file_id = hashlib.sha1(download_url.encode('utf-8')).hexdigest()
                            
                            if file_id:
                                processed_files += 1
                                progress_value = 50 + (processed_files / total_files_to_process * 50)
                                self.update_progress(progress_value)
                                
                                self.log(f"File: {title} (ID: {file_id})", "INFO")
                                
                                if file_id not in self.downloaded_files[safe_course_name]:
                                    if self.download_file(download_url, safe_course_name, title, file_id):
                                        course_new_files += 1
                                        self.downloaded_files[safe_course_name].append(file_id)
                                        self.course_stats[course.title]["downloaded"] += 1
                                        # Update file count display
                                        self.update_file_counts(course.title, 
                                                              self.course_stats[course.title]["total"],
                                                              self.course_stats[course.title]["downloaded"])
                                else:
                                    self.log("  Already downloaded", "INFO")
                
                self.log(f"Downloaded {course_new_files} new files for {course.title}", "SUCCESS")
                total_new_files += course_new_files
                
            except Exception as e:
                self.log(f"Error processing course {course.title}: {e}", "ERROR")
                continue

        self.update_progress(100)
        return total_new_files

    def resolve_file_url(self, file_page_url):
        # Given a resource page URL, return a direct downloadable file URL if possible.
        try:
            r = self.session.get(file_page_url, headers=self.headers, allow_redirects=True, timeout=30)
            r.raise_for_status()
            content_type = r.headers.get('Content-Type', '')
            # If response is not HTML, it's probably the actual file
            if content_type and not content_type.startswith('text/html'):
                return r.url

            soup = BeautifulSoup(r.text, 'html.parser')
            # Look for obvious direct links to pluginfile or files
            for a in soup.find_all('a', href=True):
                href = a['href']
                if 'pluginfile.php' in href or 'forcedownload' in href or re.search(r'\.(pdf|docx|doc|pptx|zip|rar|jpg|jpeg|png|txt)$', href, re.I):
                    return urljoin(r.url, href)

            # Some resources are inside iframes
            iframe = soup.find('iframe', src=True)
            if iframe and iframe['src']:
                src = iframe['src']
                if 'pluginfile.php' in src or re.search(r'\.(pdf|jpg|png|txt)$', src, re.I):
                    return urljoin(r.url, src)

            # Fallback to the final URL (may still be a page)
            return r.url
        except Exception:
            return file_page_url

    def download_file(self, file_url, course_folder, title, file_id):
        # Download a single file
        try:
            # Ensure absolute URL
            file_url = urljoin(file_url, file_url)
            file_request = self.session.get(file_url, headers=self.headers, 
                                          allow_redirects=True, timeout=30)
            file_request.raise_for_status()
            
            # Get filename from URL or Content-Disposition header
            filename = None
            
            # Try Content-Disposition header first
            if 'Content-Disposition' in file_request.headers:
                cd = file_request.headers['Content-Disposition']
                if 'filename=' in cd:
                    filename = cd.split('filename=')[1].strip('"\'')
            
            # Fallback to URL
            if not filename:
                filename = unquote(file_request.url.split('/')[-1].split('?')[0])
            
            # Final fallback
            if not filename or filename == '':
                filename = f"file_{file_id}"
            
            # Sanitize filename
            filename = self.sanitize_filename(filename)
            
            file_path = os.path.join(course_folder, filename)
            
            # Check if file already exists (by filename)
            if not os.path.exists(file_path):
                self.log(f"  Downloading: {filename}", "INFO")
                with open(file_path, "wb") as file_stream:
                    file_stream.write(file_request.content)
                return True
            else:
                self.log(f"  File exists: {filename}", "INFO")
                return True
                
        except Exception as e:
            self.log(f"  Error downloading file: {e}", "ERROR")
            return False

    def run_download(self, username, password, organization):
        # Main download procedure
        try:
            self.is_running = True
            self.course_stats = {}
            self.load_downloaded_files()
            
            if not self.login(username, password, organization):
                self.log("Login failed!", "ERROR")
                return
            
            courses = self.get_courses()
            if not courses:
                self.log("No courses found!", "WARNING")
                return
            
            self.log(f"Found {len(courses)} courses", "INFO")
            
            total_new_files = self.download_course_files(courses)
            
            self.save_downloaded_files()
            self.log(f"\nCompleted! Downloaded {total_new_files} new files.", "SUCCESS")
            
        except Exception as e:
            self.log(f"Fatal error: {e}", "ERROR")
        finally:
            self.is_running = False


class ModernButton(ttk.Button):
    # Custom button with modern styling
    def __init__(self, parent, **kwargs):
        style = ttk.Style()
        style.configure('Modern.TButton', font=('Segoe UI', 10), padding=8)
        kwargs['style'] = 'Modern.TButton'
        super().__init__(parent, **kwargs)


class ModernEntry(ttk.Entry):
    # Custom entry with modern styling
    def __init__(self, parent, **kwargs):
        style = ttk.Style()
        style.configure('Modern.TEntry', font=('Segoe UI', 10), padding=5)
        kwargs['style'] = 'Modern.TEntry'
        super().__init__(parent, **kwargs)


class ElearningApp:
    def __init__(self, root):
        self.root = root
        self.root.title("UniBA E-Learning Downloader")
        self.root.geometry("1200x700")  # Wider window for chart
        
        # Set background color for root
        self.root.configure(bg='#f0f2f5')
        
        # Center window on screen
        self.center_window()
        
        # Set custom styles
        self.setup_styles()
        
        self.download_manager = DownloadManager(
            progress_callback=self.update_progress_bar,
            file_count_callback=self.update_file_count_display
        )
        self.course_file_counts = {}
        
        self.setup_ui()
        
        # Start log updater
        self.update_log()

    def center_window(self):
        # Center the window on the screen
        self.root.update_idletasks()
        width = 1200
        height = 700
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def setup_styles(self):
        # Setup custom ttk styles
        style = ttk.Style()
        
        # Configure styles for modern look
        style.theme_use('clam')
        
        # Configure button styles
        style.configure('Primary.TButton', font=('Segoe UI', 10, 'bold'),
                       padding=10)
        style.map('Primary.TButton',
                 background=[('active', '#2980b9'), ('disabled', '#bdc3c7')])
        
        style.configure('Secondary.TButton', font=('Segoe UI', 10),
                       padding=8)
        
        # Configure progress bar
        style.configure('Custom.Horizontal.TProgressbar', 
                       troughcolor='#ecf0f1',
                       background='#3498db',
                       lightcolor='#3498db',
                       darkcolor='#2980b9',
                       bordercolor='#ecf0f1')

    def setup_ui(self):
        # Setup the user interface
        # Main container with padding - use tk.Frame for background color
        main_container = tk.Frame(self.root, bg='#f0f2f5')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel for controls and log
        left_panel = tk.Frame(main_container, bg='#f0f2f5')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Right panel for chart
        right_panel = tk.Frame(main_container, bg='#f0f2f5', width=400)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(20, 0))
        
        # Header Section
        header_frame = tk.Frame(left_panel, bg='#f0f2f5')
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Title with icon emoji
        title_label = tk.Label(header_frame, 
                               text="📚 UniBA E-Learning Downloader",
                               font=('Segoe UI', 18, 'bold'),
                               fg='#2c3e50',
                               bg='#f0f2f5')
        title_label.pack(anchor=tk.W)
        
        subtitle_label = tk.Label(header_frame,
                                  text="Download course materials automatically",
                                  font=('Segoe UI', 11),
                                  fg='#7f8c8d',
                                  bg='#f0f2f5')
        subtitle_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Card for login form - use tk.Frame
        card_frame = tk.Frame(left_panel, bg='white', relief='solid', 
                             borderwidth=1, padx=20, pady=20)
        card_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Login form header
        form_header = tk.Label(card_frame, 
                               text="Login Credentials",
                               font=('Segoe UI', 12, 'bold'),
                               fg='#2c3e50',
                               bg='white')
        form_header.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 15))
        
        # Username field
        tk.Label(card_frame, text="Username:", 
                 font=('Segoe UI', 10, 'bold'),
                 fg='#34495e',
                 bg='white').grid(row=1, column=0, sticky=tk.W, pady=8)
        self.username_entry = ModernEntry(card_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=8)
        
        # Password field
        tk.Label(card_frame, text="Password:", 
                 font=('Segoe UI', 10, 'bold'),
                 fg='#34495e',
                 bg='white').grid(row=2, column=0, sticky=tk.W, pady=8)
        self.password_entry = ModernEntry(card_frame, width=30, show="●")
        self.password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=8)
        
        # Organization field
        tk.Label(card_frame, text="Organization:", 
                 font=('Segoe UI', 10, 'bold'),
                 fg='#34495e',
                 bg='white').grid(row=3, column=0, sticky=tk.W, pady=8)
        self.org_entry = ModernEntry(card_frame, width=30)
        self.org_entry.insert(0, "studenti-uniba")
        self.org_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=8)
        
        # Configure grid column weights
        card_frame.columnconfigure(1, weight=1)
        
        # Progress Section
        progress_frame = tk.Frame(left_panel, bg='#f0f2f5')
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Progress bar with label
        self.progress_label = tk.Label(progress_frame,
                                      text="Progress: 0%",
                                      font=('Segoe UI', 10),
                                      fg='#2c3e50',
                                      bg='#f0f2f5')
        self.progress_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.progress_bar = ttk.Progressbar(progress_frame,
                                          style='Custom.Horizontal.TProgressbar',
                                          mode='determinate',
                                          length=100)
        self.progress_bar.pack(fill=tk.X)
        
        # Status and Button Section
        status_button_frame = tk.Frame(left_panel, bg='#f0f2f5')
        status_button_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Status label
        status_frame = tk.Frame(status_button_frame, bg='#f0f2f5')
        status_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        tk.Label(status_frame, 
                 text="Status:",
                 font=('Segoe UI', 10, 'bold'),
                 fg='#34495e',
                 bg='#f0f2f5').pack(side=tk.LEFT)
        
        self.status_label = tk.Label(status_frame,
                                     text="Ready",
                                     font=('Segoe UI', 10),
                                     fg='#27ae60',
                                     bg='#f0f2f5')
        self.status_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Buttons
        button_frame = tk.Frame(status_button_frame, bg='#f0f2f5')
        button_frame.pack(side=tk.RIGHT)
        
        self.download_button = ttk.Button(button_frame, 
                                         text="🚀 Start Download", 
                                         style='Primary.TButton',
                                         command=self.start_download)
        self.download_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, 
                                      text="🗑️ Clear Log", 
                                      style='Secondary.TButton',
                                      command=self.clear_log)
        self.clear_button.pack(side=tk.LEFT)
        
        self.show_chart_button = ttk.Button(button_frame,
                                           text="📊 Update Chart",
                                           style='Secondary.TButton',
                                           command=self.update_chart)
        self.show_chart_button.pack(side=tk.LEFT, padx=(10, 0))
        
        # File Counts Display
        self.file_counts_frame = tk.Frame(left_panel, bg='#f0f2f5')
        self.file_counts_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.file_counts_label = tk.Label(self.file_counts_frame,
                                         text="Course Files: Not scanned yet",
                                         font=('Segoe UI', 10),
                                         fg='#7f8c8d',
                                         bg='#f0f2f5',
                                         justify=tk.LEFT)
        self.file_counts_label.pack(anchor=tk.W)
        
        # Log Section Card
        log_card = tk.Frame(left_panel, bg='white', relief='solid', 
                           borderwidth=1, padx=15, pady=15)
        log_card.pack(fill=tk.BOTH, expand=True)
        
        # Log header
        log_header = tk.Frame(log_card, bg='white')
        log_header.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(log_header, 
                 text="Activity Log",
                 font=('Segoe UI', 11, 'bold'),
                 fg='#2c3e50',
                 bg='white').pack(side=tk.LEFT)
        
        # Log level indicators
        level_frame = tk.Frame(log_header, bg='white')
        level_frame.pack(side=tk.RIGHT)
        
        levels = [
            ("INFO", "#3498db"),
            ("SUCCESS", "#27ae60"),
            ("WARNING", "#f39c12"),
            ("ERROR", "#e74c3c")
        ]
        
        for level, color in levels:
            lbl = tk.Label(level_frame, 
                          text="●",
                          font=('Arial', 12),
                          fg=color,
                          bg='white')
            lbl.pack(side=tk.LEFT, padx=(10, 2))
            lbl = tk.Label(level_frame,
                          text=level,
                          font=('Segoe UI', 8),
                          fg='#7f8c8d',
                          bg='white')
            lbl.pack(side=tk.LEFT, padx=(0, 10))
        
        # Log text area with scrollbar
        log_container = tk.Frame(log_card, bg='white')
        log_container.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_container,
                                                 width=60,
                                                 height=20,
                                                 font=('Consolas', 9),
                                                 bg='#f8f9fa',
                                                 fg='#2c3e50',
                                                 relief='flat',
                                                 borderwidth=0,
                                                 wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tag colors for different log levels
        self.log_text.tag_config("INFO", foreground="#3498db")
        self.log_text.tag_config("SUCCESS", foreground="#27ae60")
        self.log_text.tag_config("WARNING", foreground="#f39c12")
        self.log_text.tag_config("ERROR", foreground="#e74c3c")
        
        # Chart Section in right panel
        chart_card = tk.Frame(right_panel, bg='white', relief='solid', 
                             borderwidth=1, padx=15, pady=15)
        chart_card.pack(fill=tk.BOTH, expand=True)
        
        # Chart header
        chart_header = tk.Frame(chart_card, bg='white')
        chart_header.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(chart_header, 
                 text="Course File Distribution",
                 font=('Segoe UI', 11, 'bold'),
                 fg='#2c3e50',
                 bg='white').pack()
        
        # Chart container
        self.chart_container = tk.Frame(chart_card, bg='white')
        self.chart_container.pack(fill=tk.BOTH, expand=True)
        
        # Initial empty chart
        self.create_empty_chart()

    def create_empty_chart(self):
        # Create an empty pie chart
        fig = Figure(figsize=(5, 4), dpi=100, facecolor='white')
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, 'No data yet\nStart download to see statistics', 
                horizontalalignment='center', verticalalignment='center',
                transform=ax.transAxes, fontsize=12, color='#7f8c8d')
        ax.set_axis_off()
        
        # Clear previous chart if exists
        for widget in self.chart_container.winfo_children():
            widget.destroy()
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_chart(self):
        # Update the pie chart with current course statistics
        if not hasattr(self.download_manager, 'course_stats') or not self.download_manager.course_stats:
            self.create_empty_chart()
            return
        
        # Prepare data for chart
        course_names = []
        file_counts = []
        colors = []
        
        # Generate colors
        cmap = plt.cm.Set3
        color_indices = np.linspace(0, 1, len(self.download_manager.course_stats))
        
        for idx, (course_name, stats) in enumerate(self.download_manager.course_stats.items()):
            if stats["total"] > 0:  # Only include courses with files
                course_names.append(f"{course_name[:15]}...\n({stats['downloaded']}/{stats['total']})")
                file_counts.append(stats["total"])
                colors.append(cmap(color_indices[idx]))
        
        if not file_counts:
            self.create_empty_chart()
            return
        
        # Create pie chart
        fig = Figure(figsize=(5, 4), dpi=100, facecolor='white')
        ax = fig.add_subplot(111)
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(file_counts, 
                                          labels=course_names if len(course_names) <= 8 else None,
                                          colors=colors,
                                          autopct='%1.1f%%',
                                          startangle=90,
                                          pctdistance=0.85,
                                          labeldistance=1.05)
        
        # Style the chart
        ax.set_title('Files per Course', fontsize=12, fontweight='bold', color='#2c3e50')
        
        # Make the chart equal aspect ratio
        ax.axis('equal')
        
        # Add legend if too many courses
        if len(course_names) > 8:
            ax.legend(wedges, course_names, title="Courses", 
                     loc="center left", bbox_to_anchor=(1, 0, 0.5, 1),
                     fontsize=8)
        
        # Style percentage text
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(9)
        
        # Style label text
        for text in texts:
            text.set_fontsize(9)
            text.set_color('#2c3e50')
        
        # Clear previous chart
        for widget in self.chart_container.winfo_children():
            widget.destroy()
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_progress_bar(self, value, max_value=None):
        # Update the progress bar with current value
        def _update():
            if max_value:
                # Scale value to 0-100
                percentage = (value / max_value) * 100
                self.progress_bar['value'] = percentage
                self.progress_label.config(text=f"Progress: {percentage:.1f}%")
            else:
                # Value is already percentage
                self.progress_bar['value'] = value
                self.progress_label.config(text=f"Progress: {value:.1f}%")
        
        # Schedule update on main thread
        self.root.after(0, _update)

    def update_file_count_display(self, course_name, total_files, downloaded_files):
        # Update the file count display for a course
        def _update():
            # Store in dictionary
            self.course_file_counts[course_name] = {
                "total": total_files,
                "downloaded": downloaded_files
            }
            
            # Update label with summary
            total_all = sum(stats["total"] for stats in self.course_file_counts.values())
            downloaded_all = sum(stats["downloaded"] for stats in self.course_file_counts.values())
            
            summary = f"Course Files: {downloaded_all}/{total_all} downloaded"
            if len(self.course_file_counts) > 0:
                summary += f" ({len(self.course_file_counts)} courses)"
            
            self.file_counts_label.config(text=summary)
        
        # Schedule update on main thread
        self.root.after(0, _update)

    def log(self, message, level="INFO"):
        # Add message to log
        self.download_manager.log(message, level)

    def update_log(self):
        # Update log text from queue
        try:
            while True:
                message = self.download_manager.log_queue.get_nowait()
                # Parse message for level coloring
                if "[INFO]" in message:
                    level = "INFO"
                elif "[SUCCESS]" in message:
                    level = "SUCCESS"
                elif "[WARNING]" in message:
                    level = "WARNING"
                elif "[ERROR]" in message:
                    level = "ERROR"
                else:
                    level = "INFO"
                
                # Insert with appropriate color
                self.log_text.insert(tk.END, message + "\n", level)
                self.log_text.see(tk.END)
                self.root.update_idletasks()
        except queue.Empty:
            pass
        
        self.root.after(100, self.update_log)

    def clear_log(self):
        # Clear the log text
        self.log_text.delete(1.0, tk.END)

    def start_download(self):
        # Start download process in separate thread
        if self.download_manager.is_running:
            messagebox.showwarning("Warning", "Download already in progress!")
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        organization = self.org_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password!")
            return

        if not organization:
            organization = "studenti-uniba"

        # Reset UI state
        self.download_button.config(state='disabled')
        self.clear_button.config(state='disabled')
        self.show_chart_button.config(state='disabled')
        self.status_label.config(text="Downloading...", fg="#f39c12")
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Progress: 0%")
        self.course_file_counts = {}
        self.file_counts_label.config(text="Course Files: Scanning...")
        
        # Clear old chart and show loading
        self.create_empty_chart()
        
        # Start download in separate thread
        thread = threading.Thread(
            target=self.run_download_thread,
            args=(username, password, organization),
            daemon=True
        )
        thread.start()

    def run_download_thread(self, username, password, organization):
        # Run download in thread
        try:
            self.download_manager.run_download(username, password, organization)
        finally:
            # Re-enable button and stop progress
            self.root.after(0, self.download_complete)

    def download_complete(self):
        # Called when download completes
        self.download_button.config(state='normal')
        self.clear_button.config(state='normal')
        self.show_chart_button.config(state='normal')
        self.status_label.config(text="Ready", fg="#27ae60")
        self.progress_bar['value'] = 100
        self.progress_label.config(text="Progress: 100%")
        self.log("Ready for next download.", "INFO")
        
        # Update chart with final statistics
        self.root.after(500, self.update_chart)


def main():
    root = tk.Tk()

    try:
        root.iconbitmap('icon.ico') 
    except:
        pass
    
    app = ElearningApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()