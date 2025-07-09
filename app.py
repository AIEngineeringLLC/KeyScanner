import os
import sys
import http.server
import socketserver
import urllib.parse
import mimetypes # For serving static files like CSS
import re # Needed for the actual scanner logic

# --- Utility to get resource path for PyInstaller ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # For development, use the script's directory
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# --- Actual Scanner Logic ---
POTENTIAL_KEY_EXTENSIONS = (
    '.pem', '.key', '.priv', '.pk', '.pfx', '.p12', '.der', # Common extensions
    '.gpg', '.asc', # PGP/GPG keys
    '.id_rsa', '.id_dsa', '.id_ecdsa', '.id_ed25519', '.id_ed25519_sk', # SSH private key files (often without extension)
    '.ppk', # PuTTY private key files
    '.crt', '.cer', '.cert', # Certificates (could be public, or contain private bundles)
    '.csr', '.req', # Certificate Signing Requests (imply a key)
    '.p7b', '.pkcs7', # PKCS#7 format (can contain certs, sometimes keys)
    'known_hosts', # Can sometimes contain private host keys if misconfigured
    'config', # SSH client config can contain keys or paths to keys
)

POTENTIAL_KEY_FILENAMES = (
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_ed25519_sk', # Common SSH key filenames (no extension)
    'ssh_host_rsa_key', 'ssh_host_dsa_key', 'ssh_host_ecdsa_key', 'ssh_host_ed25519_key', # Server host key names
    'server.key', 'client.key', 'private.key', 'id_key', # Generic application key names
    'key.pem', 'certificate.pem', 'cert.pem', # Common certificate/key combo names
    'cert', 'key', # Very generic, will rely heavily on content scan
)

KEY_CONTENT_PATTERNS = {
    "RSA_PRIVATE": b"-----BEGIN RSA PRIVATE KEY-----",
    "DSA_PRIVATE": b"-----BEGIN DSA PRIVATE KEY-----",
    "EC_PRIVATE": b"-----BEGIN EC PRIVATE KEY-----", # ECDSA keys
    "OPENSSH_PRIVATE": b"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP_PRIVATE": b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PKCS8_PRIVATE": b"-----BEGIN PRIVATE KEY-----", # Generic PKCS#8
    "ENCRYPTED_INDICATORS": [ # These indicate encryption for *any* key type
        b"Proc-Type: 4,ENCRYPTED",
        b"ENCRYPTED PRIVATE KEY",
        b"DEK-Info:", 
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ],
    "PUTTY_PPK": b"PuTTY-User-Key-File-2:",
    "CERTIFICATE": b"-----BEGIN CERTIFICATE-----", # Public certificate
    "CERTIFICATE_REQUEST": b"-----BEGIN CERTIFICATE REQUEST-----", # Certificate signing request
    "NEW_CERTIFICATE_REQUEST": b"-----BEGIN NEW CERTIFICATE REQUEST-----", # Alternative CSR header
    "PKCS7": b"-----BEGIN PKCS7-----", # PKCS#7 bundle
    # Specific patterns for common keys if highly confident (e.g., AWS EC2 usually has MII prefix)
    "AWS_EC2_PEM": b"-----BEGIN RSA PRIVATE KEY-----\nMII", 
}

# Define which patterns correspond to private keys, public certs, or CSRs
PRIVATE_KEY_PATTERNS = [
    "RSA_PRIVATE", "DSA_PRIVATE", "EC_PRIVATE", "OPENSSH_PRIVATE", 
    "PGP_PRIVATE", "PKCS8_PRIVATE", "PUTTY_PPK", "AWS_EC2_PEM"
]
PUBLIC_CERT_PATTERNS = ["CERTIFICATE", "PKCS7"]
CSR_PATTERNS = ["CERTIFICATE_REQUEST", "NEW_CERTIFICATE_REQUEST"]

UNSECURENESS_RANK = {
    "Unknown": 0,
    "Unknown (Encrypted)": 0,
    "DSA": 1,
    "RSA": 2,
    "EC": 3,
    "OPENSSH": 3,
    "PGP": 2,
    "PKCS8": 2,
    "PuTTY_PPK": 2,
    "AWS EC2 RSA": 2, # Treat specific types
}

class KeyResult:
    def __init__(self, file_path, detected_algorithm="Unknown", bit_size="N/A", is_encrypted=False,
                 analysis_error=None, key_type="Unknown"): # Default to "Unknown"
        self.file_path = file_path
        self.detected_algorithm = detected_algorithm
        self.bit_size = bit_size
        self.is_encrypted = is_encrypted
        self.analysis_error = analysis_error
        self.key_type = key_type # Will be "Private Key", "Public Certificate", "Certificate Request" etc.
        canonical_algo = self.detected_algorithm.split(' ')[0]
        self.unsecureness_rank = UNSECURENESS_RANK.get(canonical_algo, 0)
        # For non-private keys, rank is low, as they are not immediately a security risk in the same way
        if self.key_type != "Private Key":
            self.unsecureness_rank = 0 

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "detected_algorithm": self.detected_algorithm,
            "bit_size": self.bit_size,
            "is_encrypted": self.is_encrypted,
            "unsecureness_rank": self.unsecureness_rank,
            "analysis_error": self.analysis_error,
            "key_type": self.key_type,
        }

    def __repr__(self):
        status = "Encrypted" if self.is_encrypted else "Unencrypted" if self.key_type == "Private Key" else self.key_type
        if self.analysis_error:
            status = f"Error: {self.analysis_error}"
        return (f"KeyResult(path='{self.file_path}', Type='{self.key_type}', Algo='{self.detected_algorithm}', "
                        f"Size='{self.bit_size}', Status='{status}', Rank={self.unsecureness_rank})")

def analyze_key_file_content(file_path):
    """
    Analyzes the content (first few KB) of a file to determine if it's a private key,
    a public certificate, or a certificate request, its type, and if it's encrypted.
    This is a heuristic and not a full cryptographic parser.
    """
    detected_algorithm = "Unknown"
    is_encrypted = False
    bit_size = "N/A"
    analysis_error = None
    key_type = "Unknown" # Default key_type

    try:
        # Check file size before attempting to read
        if not os.path.exists(file_path): # Check again if exists after path validation
            return KeyResult(file_path=file_path, analysis_error="File not found")
        if os.path.getsize(file_path) == 0:
            return KeyResult(file_path=file_path, analysis_error="File is empty")

        with open(file_path, 'rb') as f:
            content = f.read(8192) # Read first 8KB for better chances of finding patterns

        # 1. Check for encryption indicators first
        for indicator in KEY_CONTENT_PATTERNS["ENCRYPTED_INDICATORS"]:
            if indicator in content:
                is_encrypted = True
                break
        
        # 2. Determine key type (Private Key, Public Certificate, CSR)
        # Prioritize private key detections as they are the primary target
        found_private_key_pattern = False
        for pattern_name in PRIVATE_KEY_PATTERNS:
            if KEY_CONTENT_PATTERNS[pattern_name] in content:
                key_type = "Private Key"
                detected_algorithm = pattern_name.replace("_PRIVATE", "").replace("_PEM", "").replace("_", " ") # Clean up name
                found_private_key_pattern = True
                if pattern_name == "AWS_EC2_PEM": detected_algorithm = "AWS EC2 RSA"
                break
        
        # If no private key, check for public certificates or CSRs
        if not found_private_key_pattern:
            for pattern_name in PUBLIC_CERT_PATTERNS:
                if KEY_CONTENT_PATTERNS[pattern_name] in content:
                    key_type = "Public Certificate"
                    detected_algorithm = pattern_name.replace("_", " ")
                    break
        
        if not found_private_key_pattern and key_type == "Unknown": # Only if no private key or public cert found yet
            for pattern_name in CSR_PATTERNS:
                if KEY_CONTENT_PATTERNS[pattern_name] in content:
                    key_type = "Certificate Request"
                    detected_algorithm = pattern_name.replace("_", " ")
                    break

        # Refine algorithm name and encryption status
        if key_type == "Unknown" and is_encrypted:
            detected_algorithm = "Unknown (Encrypted)"
            key_type = "Possibly Encrypted Key/Cert" # More generic if type unknown
        elif is_encrypted and key_type == "Private Key":
            detected_algorithm += " (Encrypted)"

    except PermissionError:
        analysis_error = "Permission Denied"
    except UnicodeDecodeError:
        analysis_error = "Not a text file (binary content)"
    except IsADirectoryError:
        analysis_error = "Path is a directory, not a file"
    except Exception as e:
        analysis_error = f"Error during analysis: {e}"

    # If no specific pattern was identified, but it was found by name/extension during initial scan,
    # it still gets recorded with "Unknown" type and algorithm, along with any analysis error.
    return KeyResult(
        file_path=file_path,
        detected_algorithm=detected_algorithm,
        bit_size=bit_size,
        is_encrypted=is_encrypted,
        analysis_error=analysis_error,
        key_type=key_type
    )

def scan_for_keys(directories, content_scan=False, follow_symlinks=False):
    """
    Scans the given directories recursively for potential private key files, public certs, or CSRs.
    :param directories: A list of directory paths to scan.
    :param content_scan: If True, performs a more thorough scan by inspecting file content
                         for key headers, regardless of filename/extension. (Slower)
    :param follow_symlinks: If True, os.walk will follow symbolic links.
    """
    all_results = []
    processed_files = set() # To store paths of files already processed to avoid duplicates

    lower_case_key_extensions = [ext.lower() for ext in POTENTIAL_KEY_EXTENSIONS]
    lower_case_key_filenames = [name.lower() for name in POTENTIAL_KEY_FILENAMES]

    # Pre-compile regex for faster content pattern matching
    compiled_patterns = []
    for pattern_category, patterns in KEY_CONTENT_PATTERNS.items():
        if pattern_category == "ENCRYPTED_INDICATORS":
            for p in patterns:
                compiled_patterns.append(re.compile(re.escape(p)))
        else: # Single pattern (e.g., RSA_PRIVATE)
            compiled_patterns.append(re.compile(re.escape(patterns)))

    for base_dir in directories:
        if not os.path.isdir(base_dir):
            continue

        try:
            # Removed aggressive filtering of .git, node_modules etc.,
            # relying more on file size/type and explicit content scan mode.
            for root, _, files in os.walk(base_dir, followlinks=follow_symlinks):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    file_lower = filename.lower()

                    if full_path in processed_files:
                        continue
                    
                    # Basic filters for performance on large/binary files, especially during content scan
                    try:
                        file_size = os.path.getsize(full_path)
                        if file_size == 0:
                            continue # Skip empty files
                        if file_size > 10 * 1024 * 1024: # 10 MB limit for content scan
                            # If it's a candidate by name/ext, we still want to analyze it,
                            # but don't attempt a blind content scan if it's too big.
                            is_candidate_by_name_or_ext = any(file_lower.endswith(ext) for ext in lower_case_key_extensions) or \
                                                           any(file_lower == name for name in lower_case_key_filenames)
                            if not is_candidate_by_name_or_ext:
                                continue # Skip very large files unless already named like a key

                        # Basic check for common binary extensions (can be expanded), unless it's a known key extension
                        is_binary_extension = any(file_lower.endswith(ext) for ext in ['.exe', '.dll', '.zip', '.rar', '.7z', '.iso', '.img', '.bin', '.mp3', '.mp4', '.jpg', '.png', '.gif', '.pdf', '.docx', '.xlsx', '.pptx', '.sqlite'])
                        if is_binary_extension and not any(file_lower.endswith(ext) for ext in lower_case_key_extensions):
                            continue # Skip binary files unless they have a known key extension

                    except FileNotFoundError:
                        continue
                    except Exception:
                        pass # Ignore other errors here for robust scanning

                    is_candidate_by_name_or_ext = False
                    if file_lower in lower_case_key_filenames:
                        is_candidate_by_name_or_ext = True
                    else:
                        for ext in lower_case_key_extensions:
                            if file_lower.endswith(ext):
                                is_candidate_by_name_or_ext = True
                                break

                    if is_candidate_by_name_or_ext:
                        result = analyze_key_file_content(full_path)
                        if result.key_type != "Unknown" or result.analysis_error: 
                            all_results.append(result)
                            processed_files.add(full_path)

                    if content_scan and full_path not in processed_files:
                        try:
                            with open(full_path, 'rb') as f:
                                head_content = f.read(8192) # Read more for content scan

                            is_key_by_content_pattern = False
                            for pattern_re in compiled_patterns:
                                if pattern_re.search(head_content):
                                    is_key_by_content_pattern = True
                                    break
                            
                            if is_key_by_content_pattern:
                                result = analyze_key_file_content(full_path)
                                if result.key_type != "Unknown" or result.analysis_error: 
                                    all_results.append(result)
                                    processed_files.add(full_path)

                        except (IOError, PermissionError, UnicodeDecodeError, IsADirectoryError):
                            pass # Silently skip files that cause issues during content read
                        except Exception as e:
                            pass # Catch all other unexpected errors during content read

        except PermissionError:
            pass # Silently skip directories where permission is denied
        except Exception as e:
            pass # Catch all other unexpected errors during os.walk

    # Sort results by unsecureness rank (private keys first), then encrypted/unencrypted
    all_results.sort(key=lambda x: (x.unsecureness_rank, x.is_encrypted, x.file_path), reverse=True)
    return all_results

# --- End of Scanner Logic ---

# --- Utility Functions ---
def get_default_scan_directories():
    """
    Returns a list of default directories to scan.
    """
    user_home = os.path.expanduser("~")
    program_data = os.getenv("PROGRAMDATA", "") # Windows
    temp_dir = os.getenv("TEMP", os.getenv("TMP", "/tmp")) # Windows/Linux
    app_data = os.getenv("APPDATA", "") # Windows Roaming Profile
    local_app_data = os.getenv("LOCALAPPDATA", "") # Windows Local Profile
    all_users_profile = os.getenv("ALLUSERSPROFILE", "") # Windows All Users

    unique_dirs = set()

    def add_dir_if_exists(path_segment):
        path = os.path.join(user_home, path_segment)
        resolved_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        if os.path.isdir(resolved_path):
            unique_dirs.add(resolved_path)

    # --- Common User-Related Directories (Cross-Platform) ---
    add_dir_if_exists('.ssh')
    add_dir_if_exists('.gnupg')
    add_dir_if_exists('.aws') # AWS CLI credentials
    add_dir_if_exists('.azure') # Azure CLI credentials
    add_dir_if_exists('.gcloud') # Google Cloud CLI credentials
    add_dir_if_exists('.kube') # Kubernetes kubeconfig files
    add_dir_if_exists('.docker') # Docker daemon config/certs
    add_dir_if_exists('.config') # General config dir (Linux/macOS modern apps)
    add_dir_if_exists(os.path.join(user_home, 'Documents')) # Use os.path.join for cross-platform compatibility
    add_dir_if_exists(os.path.join(user_home, 'Downloads'))
    add_dir_if_exists(os.path.join(user_home, 'Desktop'))
    add_dir_if_exists('Projects') # Common dev dir
    add_dir_if_exists('Code') # Common dev dir
    add_dir_if_exists('Development') # Common dev dir
    add_dir_if_exists('OneDrive') # Many users save files here

    # Add temp_dir if it exists and is a directory
    resolved_temp_dir = os.path.normcase(os.path.normpath(os.path.abspath(temp_dir)))
    if os.path.isdir(resolved_temp_dir):
        unique_dirs.add(resolved_temp_dir)

    # --- Windows-Specific Directories ---
    if sys.platform == "win32":
        # System-wide keys (often requires Admin)
        if program_data:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_data, 'Microsoft', 'Crypto', 'RSA', 'MachineKeys')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_data, 'OpenSSH')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_data, 'Docker', 'pki'))))) # Docker Desktop
        if all_users_profile:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(all_users_profile, 'ssh'))))) # Alternative SSH location

        # User-specific application data
        if app_data:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(app_data, 'OpenSSH')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(app_data, 'PuTTY'))))) # PuTTY config/sessions (keys referenced, sometimes stored)
        if local_app_data:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(local_app_data, 'OpenSSH'))))) # Common for user OpenSSH
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(local_app_data, 'Programs', 'PuTTY'))))) # PuTTY installation directory, sometimes contains keys
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(local_app_data, 'Microsoft', 'SSH'))))) # Built-in Windows SSH client

        # Program Files locations (Git, OpenSSH, etc.)
        program_files = os.environ.get('ProgramFiles')
        program_files_x86 = os.environ.get('ProgramFiles(x86)')
        if program_files:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_files, 'Git', 'etc', 'ssh')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_files, 'OpenSSH')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_files, 'PuTTY')))))
        if program_files_x86 and program_files_x86 != program_files: # Avoid duplicating if same path
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(program_files_x86, 'Git', 'etc', 'ssh')))))

        # Windows System32 (e.g., built-in OpenSSH server)
        system_root = os.environ.get('SystemRoot')
        if system_root:
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(system_root, 'System32', 'OpenSSH')))))
            unique_dirs.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(system_root, 'System32', 'config', 'systemprofile', '.ssh'))))) # System account SSH

    # --- Linux/macOS-Specific Directories ---
    else: # Assuming Linux/macOS
        # System-wide locations (often requires root/sudo)
        unique_dirs.add('/etc/ssh') # System-wide SSH keys
        unique_dirs.add('/etc/ssl/private') # Common for server private keys (Apache, Nginx)
        unique_dirs.add('/etc/pki/tls/private') # Alternative for certs/keys
        unique_dirs.add('/var/lib/jenkins/.ssh') # Common for CI/CD server keys
        unique_dirs.add('/var/lib/docker/volumes') # Docker volumes (might contain keys)
        unique_dirs.add('/var/lib/flatpak/app/*/*/data/.ssh') # Flatpak apps (wildcard - manual check)
        unique_dirs.add('/var/snap/snapd/common/ssh') # Snap packages

        # Application/Installation directories
        unique_dirs.add('/opt') # Common for third-party software installations
        unique_dirs.add('/usr/local/etc') # Homebrew/local installs' config
        unique_dirs.add('/usr/local/share') # Homebrew/local installs' data
        unique_dirs.add('/usr/local/apache2/conf') # Common Apache location
        unique_dirs.add('/usr/local/nginx/conf') # Nginx conf

        # Cloud-related common paths
        unique_dirs.add('/usr/bin/.ssh') # Some cloud init scripts might place ssh keys here
        unique_dirs.add('/snap/bin/.ssh') # If running via Snap

    # Filter out empty strings or paths that don't actually exist
    final_dirs = sorted([d for d in list(unique_dirs) if d and os.path.isdir(d)])
    return final_dirs

def is_admin_windows():
    """Checks if the script is running with admin privileges (Windows specific)."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False

# --- Homegrown HTTP Request Handler ---
class HomegrownHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def _read_template(self, filename):
        """Reads an HTML template file."""
        # Use resource_path for PyInstaller compatibility
        file_path = resource_path(filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            self.send_error(404, f"Template file not found: {file_path}. Please ensure '{filename}' is bundled correctly.")
            return None
        except Exception as e:
            self.send_error(500, f"Error reading template {filename}: {e}")
            return None

    def _serve_file(self, filename, content_type):
        """Serves a static file (like CSS, JPG)."""
        # Use resource_path for PyInstaller compatibility
        file_path = resource_path(filename)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            try:
                with open(file_path, 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(os.path.getsize(file_path)))
                    self.end_headers()
                    self.wfile.write(f.read())
            except Exception as e:
                self.send_error(500, f"Error serving file: {e}")
        else:
            self.send_error(404, f"File not found: {file_path}")

    def _send_response_html(self, html_content, status_code=200):
        """Helper to send HTTP response with HTML content."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def do_GET(self):
        """Handles GET requests."""
        if self.path == '/' or self.path.startswith('/?'):
            self._handle_index()
        elif self.path == '/style.css':
            self._serve_file('style.css', 'text/css')
        elif self.path == '/logo.jpg':
            self._serve_file('logo.jpg', 'image/jpeg')
        else:
            self.send_error(404, "Not Found")

    def _handle_index(self, error_message=None):
        """Generates and sends the index page."""
        template = self._read_template('index.html')
        if template is None:
            return # Error already sent by _read_template

        scan_dirs = get_default_scan_directories()
        checkboxes_html = []
        for i, path in enumerate(scan_dirs):
            admin_note_html = ''
            path_lower = path.lower()
            
            # Heuristic to suggest admin privileges
            if sys.platform == "win32":
                if "programdata" in path_lower or "machinekeys" in path_lower or \
                   "program files" in path_lower or "system32" in path_lower or \
                   "windows" in path_lower or "all users" in path_lower:
                    admin_note_html = '<span class="admin-note">(Admin Privileges Recommended)</span>'
            else: # Linux/macOS
                if path_lower.startswith('/etc/') or path_lower.startswith('/var/') or \
                   path_lower.startswith('/opt/') or path_lower.startswith('/usr/local/') or \
                   path_lower.startswith('/snap/') or path_lower.startswith('/run/'):
                    admin_note_html = '<span class="admin-note">(Root/Sudo Privileges Recommended)</span>'
            
            escaped_path = urllib.parse.quote_plus(path) 

            checkboxes_html.append(f"""
                <div class="directory-item">
                    <input type="checkbox" id="dir_{i}" name="scan_directories" value="{escaped_path}" checked>
                    <label for="dir_{i}">{path} {admin_note_html}</label>
                </div>
            """)
        
        no_dirs_message_placeholder = ""
        if not scan_dirs:
            no_dirs_message_placeholder = """
            <div class="no-directories-found">
                No default scan directories found or accessible. Please ensure you have Python, and necessary directories exist.
                You might need to run the script with elevated privileges to find system paths.
            </div>
            """

        error_message_placeholder = ""
        if error_message:
            error_message_placeholder = f'<div class="error-message">{error_message}</div>'

        html_content = template.replace('PLACEHOLDER_CHECKBOXES', "\n".join(checkboxes_html))
        html_content = html_content.replace('PLACEHOLDER_NO_DIRS_MESSAGE', no_dirs_message_placeholder)
        html_content = html_content.replace('PLACEHOLDER_ERROR_MESSAGE', error_message_placeholder)
        
        self._send_response_html(html_content)

    def do_POST(self):
        """Handles POST requests, specifically for /scan."""
        if self.path == '/scan':
            self._handle_scan()
        else:
            self.send_error(404, "Not Found")

    def _handle_scan(self):
        """Processes the scan request and displays results."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data_bytes = self.rfile.read(content_length)
        post_data_str = post_data_bytes.decode('utf-8')
        
        parsed_data = urllib.parse.parse_qs(post_data_str)
        
        selected_dirs = [urllib.parse.unquote_plus(d) for d in parsed_data.get('scan_directories', [])]
        content_scan_enabled = 'content_scan' in parsed_data and parsed_data['content_scan'][0] == 'true'
        follow_symlinks_enabled = 'follow_symlinks' in parsed_data and parsed_data['follow_symlinks'][0] == 'true'

        if not selected_dirs:
            self._handle_index(error_message="Please select at least one directory to scan.")
            return

        results = scan_for_keys(selected_dirs, content_scan=content_scan_enabled, follow_symlinks=follow_symlinks_enabled)

        # Distinguish results more clearly in the output
        private_keys_found = [r for r in results if r.key_type == "Private Key"]
        public_certs_found = [r for r in results if r.key_type == "Public Certificate"]
        certificate_requests_found = [r for r in results if r.key_type == "Certificate Request"]
        other_found = [r for r in results if r.key_type not in ["Private Key", "Public Certificate", "Certificate Request"]]

        is_admin_check = is_admin_windows()
        admin_status_class = "true" if is_admin_check else "false"
        admin_status_text = "Running as Administrator (Windows)" if is_admin_check else "NOT running as Administrator (Windows). Some paths may be inaccessible. Run as Admin for full scan."
        if sys.platform != "win32":
            admin_status_text = "On non-Windows OS, ensure appropriate privileges (e.g., sudo) for full scan of system paths."
            admin_status_class = "" 

        # Prepare HTML for Private Keys table
        private_keys_table_html = []
        if private_keys_found:
            private_keys_table_html.append("""
            <div class="results-table-container">
            <h3>Discovered Private Keys</h3>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Algorithm</th>
                        <th>Bit Size</th>
                        <th>Encryption</th>
                        <th>Errors/Notes</th>
                    </tr>
                </thead>
                <tbody>
            """)
            for res in private_keys_found:
                encryption_status = "Encrypted" if res.is_encrypted else "Unencrypted" if res.detected_algorithm != "Unknown" else "Undetermined"
                private_keys_table_html.append(f"""
                <tr class="{'encrypted' if res.is_encrypted else ''}">
                    <td>{res.file_path}</td>
                    <td>{res.detected_algorithm}</td>
                    <td>{res.bit_size if res.bit_size else 'N/A'}</td>
                    <td>{encryption_status}</td>
                    <td class="{'error-cell' if res.analysis_error else ''}">{res.analysis_error if res.analysis_error else 'None'}</td>
                </tr>
                """)
            private_keys_table_html.append("</tbody></table></div>")
            private_keys_table_html = "".join(private_keys_table_html)
        else:
            private_keys_table_html = '<p class="no-results">No unencrypted private keys found matching common patterns and headers.</p>'

        # Prepare HTML for Other Cryptographic Artifacts
        other_artifacts_html = []
        all_other_findings = public_certs_found + certificate_requests_found + other_found
        if all_other_findings:
            other_artifacts_html.append("""
            <div class="results-table-container other-artifacts">
            <h3>Other Cryptographic Artifacts (Certs, CSRs, Encrypted/Unknown)</h3>
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Type</th>
                        <th>Algorithm</th>
                        <th>Encryption</th>
                        <th>Errors/Notes</th>
                    </tr>
                </thead>
                <tbody>
            """)
            for res in all_other_findings:
                encryption_status = "Encrypted" if res.is_encrypted and res.key_type != "Public Certificate" else "No"
                if res.key_type == "Public Certificate" and res.is_encrypted: encryption_status = "Cert is Encrypted (uncommon)" # Unlikely for public cert
                if res.key_type in ["Certificate Request", "Public Certificate"]: encryption_status = "N/A" # Encryption not applicable normally

                other_artifacts_html.append(f"""
                <tr>
                    <td>{res.file_path}</td>
                    <td>{res.key_type}</td>
                    <td>{res.detected_algorithm}</td>
                    <td>{encryption_status}</td>
                    <td class="{'error-cell' if res.analysis_error else ''}">{res.analysis_error if res.analysis_error else 'None'}</td>
                </tr>
                """)
            other_artifacts_html.append("</tbody></table></div>")
            other_artifacts_html = "".join(other_artifacts_html)
        else:
            other_artifacts_html = '<p class="no-results">No other cryptographic artifacts (public certificates, CSRs, or unknown encrypted files) were found.</p>'

        template = self._read_template('results.html')
        if template is None:
            return # Error already sent by _read_template

        # Placeholder for common display variables
        html_content_final = template.replace('PLACEHOLDER_NUM_TOTAL_RESULTS', str(len(results)))
        html_content_final = html_content_final.replace('PLACEHOLDER_NUM_PRIVATE_KEYS', str(len(private_keys_found)))
        html_content_final = html_content_final.replace('PLACEHOLDER_NUM_PUBLIC_CERTS', str(len(public_certs_found)))
        html_content_final = html_content_final.replace('PLACEHOLDER_NUM_CS_REQUESTS', str(len(certificate_requests_found)))
        
        display_selected_dirs = [d.replace(os.path.expanduser("~"), "~") for d in selected_dirs]
        display_selected_dirs_str = ", ".join(display_selected_dirs[:5])
        if len(selected_dirs) > 5:
            display_selected_dirs_str += f" and {len(selected_dirs) - 5} more..."
        
        html_content_final = html_content_final.replace('PLACEHOLDER_SCANNED_DIRECTORIES', display_selected_dirs_str)
        html_content_final = html_content_final.replace('PLACEHOLDER_IS_ADMIN_CLASS', admin_status_class) # Fixed typo 'PLACEER'
        html_content_final = html_content_final.replace('PLACEHOLDER_ADMIN_STATUS_TEXT', admin_status_text)
        html_content_final = html_content_final.replace('PLACEHOLDER_PRIVATE_KEYS_TABLE', private_keys_table_html)
        html_content_final = html_content_final.replace('PLACEHOLDER_OTHER_ARTIFACTS_TABLE', other_artifacts_html)
        html_content_final = html_content_final.replace('PLACEHOLDER_CONTENT_SCAN_STATUS', 'Enabled' if content_scan_enabled else 'Disabled')
        html_content_final = html_content_final.replace('PLACEHOLDER_SYMLINK_STATUS', 'Enabled' if follow_symlinks_enabled else 'Disabled')

        self._send_response_html(html_content_final)

# --- Server Start ---
if __name__ == '__main__':
    PORT = 8000
    handler = HomegrownHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True 
    # Use 0.0.0.0 to listen on all available interfaces, including localhost
    with socketserver.TCPServer(("", PORT), handler) as httpd: 
        print(f"Serving 'Local Classic Key Scanner' (Homegrown) on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            # Ensure proper shutdown if the server is running in a console
            httpd.shutdown() 
            httpd.server_close()
        # For a --windowed app, the console will not stay open.
        # Consider adding a small delay or a GUI message before exiting if needed.
        # Example: time.sleep(2)