import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import threading
import re

# ---------- Helper Functions ----------
def is_valid_username(username):
    return re.match(r"^[a-zA-Z0-9\.\-_]{3,}$", username) is not None

def is_valid_hostname(hostname):
    return re.match(r"^[a-zA-Z0-9\-\.]{1,64}$", hostname) is not None

def run_powershell(command):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            output = result.stdout.strip() or "(no output)"
            return output, "success"
        else:
            output = result.stderr.strip() or "Unknown PowerShell error."
            return output, "error"
    except Exception as e:
        return f"Error running command: {e}", "error"

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip(), "success"
        else:
            return result.stderr.strip() or "(command failed)", "error"
    except Exception as e:
        return f"Error running command: {e}", "error"

def log(message, level="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    debug_box.config(state="normal")
    tag = {"info": "gray", "success": "green", "error": "red", "table": "blue"}.get(level, "gray")

    debug_box.insert(tk.END, f"[{timestamp}] ", ("timestamp",))
    debug_box.insert(tk.END, message + "\n", (tag,))
    debug_box.see(tk.END)

def block_edit(event):
    if event.keysym in (
        "Left", "Right", "Up", "Down", "Home", "End",
        "Shift_L", "Shift_R", "Control_L", "Control_R"
    ):
        return
    if event.state & 0x4 and event.keysym.lower() == "c":
        return
    return "break"

def copy_debug_log(event=None):
    debug_box.config(state="normal")
    data = debug_box.get(1.0, tk.END)
    root.clipboard_clear()
    root.clipboard_append(data)
    debug_box.config(state="normal")

# ---------- Progress Indicator ----------
def start_progress():
    pb.start()
    root.config(cursor="wait")
    for btn in action_buttons:
        btn.config(state="disabled")

def stop_progress():
    pb.stop()
    root.config(cursor="")
    for btn in action_buttons:
        btn.config(state="normal")

# ---------- User Actions ----------
def with_progress(func):
    def wrapper(*args, **kwargs):
        threading.Thread(target=lambda: (start_progress(), func(*args, **kwargs), stop_progress())).start()
    return wrapper

@with_progress
def check_user_status():
    user = user_entry.get().strip()
    if not is_valid_username(user):
        messagebox.showwarning("Missing/Invalid Username", "Enter a valid username (min 3 alphanum chars).")
        return
    cmd = (
        f"Import-Module ActiveDirectory; "
        f"$u = Get-ADUser -Identity '{user}' -Properties LockedOut,Enabled; "
        f'if ($u) {{ "Locked Out: $($u.LockedOut) | Enabled: $($u.Enabled)" }} '
        f'else {{ "User not found." }}'
    )
    log(f"[User] Checking status for {user}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def unlock_or_enable_user():
    user = user_entry.get().strip()
    if not is_valid_username(user):
        messagebox.showwarning("Missing/Invalid Username", "Enter a valid username (min 3 alphanum chars).")
        return
    choice = messagebox.askquestion("Action", "Unlock account (Yes) or Enable account (No)?")
    if choice == "yes":
        if not messagebox.askokcancel("Confirm", f"Are you sure you want to unlock '{user}'?"):
            return
        cmd = f"Import-Module ActiveDirectory; Unlock-ADAccount -Identity '{user}'"
        log(f"[User] Unlocking account {user}...", "info")
    else:
        if not messagebox.askokcancel("Confirm", f"Are you sure you want to enable '{user}'?"):
            return
        cmd = f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{user}'"
        log(f"[User] Enabling account {user}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def force_pw_change():
    user = user_entry.get().strip()
    if not is_valid_username(user):
        messagebox.showwarning("Missing/Invalid Username", "Enter a valid username (min 3 alphanum chars).")
        return
    if not messagebox.askokcancel("Confirm", f"Force password change at next logon for '{user}'?"):
        return
    cmd = (
        f"Import-Module ActiveDirectory; "
        f"Set-ADUser -Identity '{user}' -ChangePasswordAtLogon $true"
    )
    log(f"[User] Forcing password change for {user}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def list_user_groups():
    user = user_entry.get().strip()
    if not is_valid_username(user):
        messagebox.showwarning("Missing/Invalid Username", "Enter a valid username (min 3 alphanum chars).")
        return
    cmd = (
        f"Import-Module ActiveDirectory; "
        f"Get-ADUser -Identity '{user}' -Properties MemberOf | "
        f"Select -ExpandProperty MemberOf"
    )
    log(f"[User] Listing group memberships for {user}...", "info")
    output, lvl = run_powershell(cmd)
    if lvl == "success" and output and output != "(no output)":
        groups = [line.split(",")[0].replace("CN=", "") for line in output.splitlines()]
        log("Groups:\n" + "\n".join(f"  •  {g}" for g in groups), "table")
    else:
        log(output, lvl)

# ---------- Host Actions ----------
@with_progress
def ping_host():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"ping -n 4 {hostname}"
    log(f"[Host] Pinging {hostname}...", "info")
    output, lvl = run_command(cmd)
    log(output, lvl)

@with_progress
def who_is_logged_on():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"quser /server:{hostname}"
    log(f"[Host] Checking who is logged on {hostname}...", "info")
    output, lvl = run_command(cmd)
    log(output, lvl)

@with_progress
def map_c_drive():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    if not messagebox.askokcancel("Confirm", f"Map {hostname}\\C$ as Z: ?"):
        return
    cmd = f"net use Z: \\\\{hostname}\\c$ /persistent:no"
    log(f"[Host] Mapping {hostname}\\C$ as Z: ...", "info")
    output, lvl = run_command(cmd)
    log(output, lvl)

@with_progress
def offer_remote_assistance():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"msra /offerra {hostname}"
    log(f"[Host] Offering Remote Assistance to {hostname}...", "info")
    output, lvl = run_command(cmd)
    log(output, lvl)

@with_progress
def force_gpo_update():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock {{ gpupdate /force }}"
    log(f"[Host] Forcing GPO update on {hostname}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def get_ip_info():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock {{ Get-NetIPConfiguration }}"
    log(f"[Host] Getting IP information from {hostname}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def get_system_info():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    # Build command carefully without f-string brace confusion
    scriptblock = (
        "Get-ComputerInfo | Select-Object OsName,OsVersion,BiosCaption,BiosSerialNumber,"
        "CsDNSHostName,CsManufacturer,CsModel,CsProcessors,OsUptime,OsInstallDate,OsRegisteredUser"
    )
    cmd = f"Invoke-Command -ComputerName '{hostname}' -ScriptBlock {{ {scriptblock} }}"
    log(f"[Host] Getting system info for {hostname}...", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

@with_progress
def enter_ps_session():
    hostname = host_entry.get().strip()
    if not is_valid_hostname(hostname):
        messagebox.showwarning("Missing/Invalid Hostname", "Enter a valid hostname (max 64 chars, no special chars).")
        return
    cmd = f"Enter-PSSession -ComputerName '{hostname}'"
    log(f"[Host] [Note] (Shows only output; interactive session not supported via GUI)", "info")
    output, lvl = run_powershell(cmd)
    log(output, lvl)

# ---------- GUI Layout ----------
root = tk.Tk()
root.title("💼 IT Support Technician Toolkit")
root.geometry("980x760")
root.resizable(True, True)

wrapper = ttk.Frame(root, padding=14)
wrapper.pack(fill="both", expand=True)

user_frame = ttk.LabelFrame(wrapper, text=" 👤 User Actions ", padding=12)
host_frame = ttk.LabelFrame(wrapper, text=" 🖥️ Host Actions ", padding=12)
debug_frame = ttk.LabelFrame(wrapper, text=" 🧩 Debug / Output Log ", padding=8)
pb_frame = ttk.Frame(wrapper)

user_frame.grid(row=0, column=0, sticky="ew", padx=8, pady=(4,4))
host_frame.grid(row=1, column=0, sticky="ew", padx=8, pady=(0,8))
pb_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(0,4))
debug_frame.grid(row=3, column=0, sticky="nsew", padx=8, pady=8)
wrapper.rowconfigure(3, weight=1)
wrapper.columnconfigure(0, weight=1)

ttk.Label(user_frame, text="Username:").grid(row=0, column=0, padx=2, pady=4, sticky="e")
user_entry = ttk.Entry(user_frame, width=40)
user_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")

user_btn_frame = ttk.Frame(user_frame)
user_btn_frame.grid(row=0, column=2, rowspan=2, padx=12, pady=2, sticky="nsew")

user_actions = [
    ("Check Status", check_user_status),
    ("Unlock / Enable", unlock_or_enable_user),
    ("Force PW Change", force_pw_change),
    ("List Groups", list_user_groups),
]

user_buttons = []
for i, (label, cmd) in enumerate(user_actions):
    b = ttk.Button(user_btn_frame, text=label, command=cmd, width=18)
    b.grid(row=i, column=0, padx=2, pady=(0 if i == 0 else 4))
    user_buttons.append(b)

ttk.Label(host_frame, text="Hostname:").grid(row=0, column=0, padx=2, pady=4, sticky="e")
host_entry = ttk.Entry(host_frame, width=40)
host_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")

host_btn_frame = ttk.Frame(host_frame)
host_btn_frame.grid(row=0, column=2, rowspan=3, padx=12, pady=2, sticky="nsew")

host_actions = [
    ("Ping", ping_host),
    ("Who Logged On", who_is_logged_on),
    ("Map C$ as Z:", map_c_drive),
    ("Remote Assist", offer_remote_assistance),
    ("Force GPO Update", force_gpo_update),
    ("Get IP Info", get_ip_info),
    ("System Info", get_system_info),
    ("Enter PS Session", enter_ps_session),
]

host_buttons = []
for i, (label, cmd) in enumerate(host_actions):
    r = i % 4
    c = i // 4
    b = ttk.Button(host_btn_frame, text=label, command=cmd, width=18)
    b.grid(row=r, column=c, padx=2, pady=(0 if r == 0 else 4))
    host_buttons.append(b)

action_buttons = user_buttons + host_buttons

pb = ttk.Progressbar(pb_frame, mode="indeterminate", length=220)
pb.pack(padx=8, pady=4, fill="x")

debug_box = scrolledtext.ScrolledText(
    debug_frame, wrap=tk.WORD, height=18, state="normal", font=("Consolas", 9)
)
debug_box.pack(fill="both", expand=True, padx=4, pady=4)
debug_box.tag_config("timestamp", foreground="gray")
debug_box.tag_config("gray", foreground="gray")
debug_box.tag_config("green", foreground="green")
debug_box.tag_config("red", foreground="red")
debug_box.tag_config("table", foreground="#004488")

debug_box.bind("<Key>", block_edit)
debug_box.bind("<Button-3>", copy_debug_log)

ttk.Label(debug_frame, text="(Right-click = Copy All; or select and Ctrl+C to copy selection)", foreground="gray").pack(anchor="e", padx=4, pady=(0,2))

log("Toolkit started successfully.", "info")

root.mainloop()
