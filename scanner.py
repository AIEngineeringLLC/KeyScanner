import os
import re

# Define common private key patterns, extensions, and filenames
# This list is not exhaustive but covers common cases.
POTENTIAL_KEY_EXTENSIONS = (
    '.pem', '.key', '.priv', '.pk', '.pfx', '.p12', '.der', # Common extensions
    '.gpg', '.asc', # PGP/GPG keys
    '.id_rsa', '.id_dsa', '.id_ecdsa', '.id_ed25519', # SSH private key files (often without extension)
    '.ppk', # PuTTY private key files
    'known_hosts', # Can sometimes contain private host keys if misconfigured
    'config', # SSH client config can contain keys or paths to keys
)

POTENTIAL_KEY_FILENAMES = (
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', # Common SSH key filenames (no extension)
    'ssh_host_rsa_key', 'ssh_host_dsa_key', 'ssh_host_ecdsa_key', 'ssh_host_ed25519_key', # Server host key names
    'server.key', 'client.key', # Generic application key names
    'key.pem', 'certificate.pem', # Common certificate/key combo names
)

# Regex patterns for content-based detection (more reliable)
# These are basic and could be improved for robustness and performance.
KEY_CONTENT_PATTERNS = {
    "RSA": b"-----BEGIN RSA PRIVATE KEY-----",
    "DSA": b"-----BEGIN DSA PRIVATE KEY-----",
    "EC": b"-----BEGIN EC PRIVATE KEY-----", # ECDSA keys
    "OPENSSH": b"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP": b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PKCS8": b"-----BEGIN PRIVATE KEY-----", # Generic PKCS#8
    "ENCRYPTED_INDICATORS": [
        b"Proc-Type: 4,ENCRYPTED",
        b"ENCRYPTED PRIVATE KEY",
        b"DEK-Info:", # Often present with encryption
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ],
    "PUTTY_PPK": b"PuTTY-User-Key-File-2:",
}

# Mapping common algorithms to a classical "unsecureness" rank (higher = more unsecure)
# This is a very simplified model and might need adjustments based on current threat models.
# Quantum-safe algorithms (like Dilithium, Falcon, CRYSTALS-Kyber) are NOT detected here,
# as standard Python doesn't have built-in support for them, and they are not widely deployed for SSH/TLS yet.
UNSECURENESS_RANK = {
    "Unknown": 0, # Cannot determine, lowest priority for ranking
    "Unknown (Encrypted)": 0, # Encrypted, but needs decryption to rank
    "DSA": 1, # Older, smaller key sizes are highly insecure. Even larger ones are less common now.
    "RSA": 2, # Common, but smaller key sizes (e.g., 1024-bit) are now considered insecure. Larger sizes (2048, 4096) are still widely used.
    "EC": 3, # Elliptic Curve (ECDSA, EdDSA variants like Ed25519) - generally considered stronger per bit than RSA/DSA. Ed25519 is often preferred.
    "OPENSSH": 3, # OpenSSH format can encapsulate various algorithms; many are modern.
    "PGP": 2, # PGP keys can be RSA or DSA, rank similar to their underlying algorithms.
    "PKCS8": 2, # Generic PKCS#8 can wrap various keys; common is RSA/EC.
    "PuTTY_PPK": 2, # PuTTY format can encapsulate various algorithms.
}


class KeyResult:
    def __init__(self, file_path, detected_algorithm="Unknown", bit_size="N/A", is_encrypted=False,
                 analysis_error=None, key_type="Private Key"):
        self.file_path = file_path
        self.detected_algorithm = detected_algorithm # e.g., "RSA", "EC", "DSA", "OPENSSH", "Unknown"
        self.bit_size = bit_size # e.g., 2048, N/A
        self.is_encrypted = is_encrypted
        self.analysis_error = analysis_error # Store errors encountered during analysis
        self.key_type = key_type
        # Assign a 'classical unsecureness' rank for sorting/prioritization
        self.unsecureness_rank = UNSECURENESS_RANK.get(self.detected_algorithm.split(' ')[0], 0)

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
        status = "Encrypted" if self.is_encrypted else "Unencrypted"
        if self.analysis_error:
            status = f"Error: {self.analysis_error}"
        return (f"KeyResult(path='{self.file_path}', Algo='{self.detected_algorithm}', "
                f"Size='{self.bit_size}', Status='{status}', Rank={self.unsecureness_rank})")


def analyze_key_file_content(file_path):
    """
    Analyzes the content (first few KB) of a file to determine if it's a private key,
    its type, and if it's encrypted.
    This is a heuristic and not a full cryptographic parser.
    """
    detected_algorithm = "Unknown"
    is_encrypted = False
    bit_size = "N/A"
    analysis_error = None

    try:
        # Read only a portion of the file for efficiency, as key headers are usually at the beginning
        with open(file_path, 'rb') as f:
            content = f.read(4096) # Read first 4KB

        # Check for encryption indicators first
        for indicator in KEY_CONTENT_PATTERNS["ENCRYPTED_INDICATORS"]:
            if indicator in content:
                is_encrypted = True
                break

        # Detect algorithm based on common headers
        if KEY_CONTENT_PATTERNS["RSA"] in content:
            detected_algorithm = "RSA"
        elif KEY_CONTENT_PATTERNS["DSA"] in content:
            detected_algorithm = "DSA"
        elif KEY_CONTENT_PATTERNS["EC"] in content:
            detected_algorithm = "EC"
        elif KEY_CONTENT_PATTERNS["OPENSSH"] in content:
            detected_algorithm = "OPENSSH"
        elif KEY_CONTENT_PATTERNS["PGP"] in content:
            detected_algorithm = "PGP"
        elif KEY_CONTENT_PATTERNS["PKCS8"] in content: # PKCS#8 is a generic envelope
            detected_algorithm = "PKCS8"
        elif KEY_CONTENT_PATTERNS["PUTTY_PPK"] in content:
            detected_algorithm = "PuTTY_PPK"

        # If encrypted, and we found an algorithm, add " (Encrypted)"
        if is_encrypted and detected_algorithm != "Unknown":
            detected_algorithm += " (Encrypted)"
        elif is_encrypted: # If it's encrypted but we don't know the type
            detected_algorithm = "Unknown (Encrypted)"

    except PermissionError:
        analysis_error = "Permission Denied"
    except Exception as e:
        analysis_error = f"Error during analysis: {e}"

    return KeyResult(
        file_path=file_path,
        detected_algorithm=detected_algorithm,
        bit_size=bit_size,
        is_encrypted=is_encrypted,
        analysis_error=analysis_error
    )


def scan_for_keys(directories, content_scan=False):
    """
    Scans the given directories recursively for potential private key files.
    :param directories: A list of directory paths to scan.
    :param content_scan: If True, performs a more thorough scan by inspecting file content
                         for key headers, regardless of filename/extension. (Slower)
    """
    all_results = []
    processed_files = set() # To store paths of files already processed to avoid duplicates

    lower_case_key_extensions = [ext.lower() for ext in POTENTIAL_KEY_EXTENSIONS]
    lower_case_key_filenames = [name.lower() for name in POTENTIAL_KEY_FILENAMES]

    for base_dir in directories:
        if not os.path.isdir(base_dir):
            print(f"Warning: Directory does not exist or is not a directory: {base_dir}")
            continue

        try:
            for root, _, files in os.walk(base_dir, followlinks=False): # followlinks=False to prevent infinite loops/scanning outside scope
                for filename in files:
                    full_path = os.path.join(root, filename)
                    file_lower = filename.lower()

                    # Skip if this file has already been added to results (e.g., via content scan if done first)
                    if full_path in processed_files:
                        continue

                    # --- First pass: Check by filename or extension ---
                    is_candidate_by_name_or_ext = False
                    if file_lower in lower_case_key_filenames:
                        is_candidate_by_name_or_ext = True
                    else:
                        for ext in lower_case_key_extensions:
                            if file_lower.endswith(ext):
                                is_candidate_by_name_or_ext = True
                                break

                    if is_candidate_by_name_or_ext:
                        # Process files identified by name/extension
                        result = analyze_key_file_content(full_path)
                        all_results.append(result)
                        processed_files.add(full_path) # Mark as processed

                    # --- Second pass: Content-based scan (if enabled and file not already processed) ---
                    if content_scan and full_path not in processed_files:
                        try:
                            # Read a small chunk to quickly check for key-like headers
                            with open(full_path, 'rb') as f:
                                head_content = f.read(4096) # Read first 4KB for content peek

                            is_key_by_content_pattern = False
                            for pattern_type, patterns in KEY_CONTENT_PATTERNS.items():
                                if isinstance(patterns, list): # Handle lists of patterns (like ENCRYPTED_INDICATORS)
                                    for p in patterns:
                                        if p in head_content:
                                            is_key_by_content_pattern = True
                                            break
                                else: # Handle single patterns
                                    if patterns in head_content:
                                        is_key_by_content_pattern = True
                                        break
                                if is_key_by_content_pattern: # Found a pattern, no need to check others
                                    break

                            if is_key_by_content_pattern:
                                # This file contains a key-like pattern, so analyze it
                                result = analyze_key_file_content(full_path)
                                all_results.append(result)
                                processed_files.add(full_path) # Mark as processed

                        except (IOError, PermissionError):
                            # Cannot read file (e.g., symlink to non-existent, permission denied), skip
                            pass
                        except Exception as e:
                            # Other unexpected errors during content read (e.g., encoding issues)
                            pass

        except PermissionError:
            print(f"Access Denied: Could not scan directory {base_dir}. Run as Administrator for full scan.")
        except Exception as e:
            print(f"Error scanning directory {base_dir}: {e}")

    # Sort results by unsecureness rank (higher rank first)
    all_results.sort(key=lambda x: x.unsecureness_rank, reverse=True)
    return all_results

# Example Usage:
if __name__ == "__main__":
    # Create some dummy files for testing
    if not os.path.exists("test_keys"):
        os.makedirs("test_keys")
    with open("test_keys/id_rsa", "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n")
    with open("test_keys/my_generic_key.txt", "w") as f:
        f.write("Some random text\n-----BEGIN DSA PRIVATE KEY-----\n...\n-----END DSA PRIVATE KEY-----\n")
    with open("test_keys/encrypted.pem", "w") as f:
        f.write("-----BEGIN ENCRYPTED PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n...\n-----END ENCRYPTED PRIVATE KEY-----\n")
    with open("test_keys/not_a_key.log", "w") as f:
        f.write("This is just a log file.")
    with open("test_keys/ssh_config", "w") as f:
        f.write("Host example.com\n  IdentityFile ~/.ssh/id_rsa_example")
    
    # Define directories to scan
    target_directories = ["test_keys"] # You can add more, e.g., os.path.expanduser("~/.ssh")

    print("\n--- Performing a standard scan (filename/extension based) ---")
    found_keys_standard = scan_for_keys(target_directories, content_scan=False)
    if found_keys_standard:
        for key in found_keys_standard:
            print(key)
    else:
        print("No keys found in standard scan.")

    print("\n--- Performing a thorough scan (content-based enabled) ---")
    # To obtain more keys, set content_scan=True
    found_keys_thorough = scan_for_keys(target_directories, content_scan=True)
    if found_keys_thorough:
        for key in found_keys_thorough:
            print(key)
    else:
        print("No keys found in thorough scan.")

    # Clean up dummy files
    import shutil
    if os.path.exists("test_keys"):
        shutil.rmtree("test_keys")