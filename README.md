# KeyScanner
This tool helps you identify unencrypted private keys, public certificates, and certificate signing requests (CSRs) stored on your local file system which might pose a security risk or indicate sensitive assets.

🚀 How to Use the Local Classic Key Scanner
This tool helps you find unencrypted keys, certificates, and CSRs on your system. Follow these steps to get started:

📁 Set Up Your Files

Make sure you have all the necessary files from the provided code in the same folder:
Your Python script (e.g., Key_scanner.py)
index.html (this is the main page)
results.html (where scan results are shown)
style.css (for styling the web pages)
logo.jpg (your logo image)
▶️ Start the Scanner

Open a terminal or command prompt.
Navigate to the folder where you saved all your files.
Run the Python script using this command:
python classic_key_scanner.py
You should see a message like: Serving 'Local Classic Key Scanner' (Homegrown) on http://localhost:8000
🌐 Open in Your Browser

Open your web browser (Chrome, Firefox, Edge, etc.).
Go to the address: http://localhost:8000
⚙️ Configure Your Scan

On the page, you'll see a list of common directories. Check the boxes for the directories you want to scan.

💡 Tip: Some system-level paths (especially on Windows in "ProgramData" or "Program Files", or Linux/macOS in /etc or /var) might require you to run the Python script as an Administrator (Windows) or with sudo (Linux/macOS) for full access!
Scan Options:

✅ Perform Deep Content Scan (Recommended): Check this box if you want the scanner to inspect the contents of files for key patterns, not just their filenames/extensions. This is much more thorough but can make the scan slower.

🔗 Follow Symbolic Links: Check this if you want the scanner to follow shortcuts to other locations. This can also increase scan time and might lead to scanning areas already included if links point inside your selected directories.

🚀 Start the Scan

Once you've selected your directories and chosen your options, click the "Start Scan" button.
✨ View Results

The browser will navigate to the results page, showing any identified private keys, public certificates, or certificate signing requests (CSRs).
Private keys that are unencrypted will be highlighted as a security risk.

⚠️ Important Scan Performance Note

⚠️Toggling on Perform Deep Content Scan and/or Follow Symbolic Links will significantly increase scan time, especially if you're scanning large hard drives or many directories.

Please be patient! For a truly comprehensive scan, it might take a while. Grab a coffee! ☕
