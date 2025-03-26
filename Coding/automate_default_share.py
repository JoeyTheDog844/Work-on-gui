# automate_default_share.py

import winreg
from tkinter import messagebox

def get_admin_share_status():
    """
    Returns True if default admin shares are disabled, False if enabled.
    """
    try:
        reg = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            0,
            winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(reg, "AutoShareWks")
        winreg.CloseKey(reg)
        return value == 0  # True means disabled
    except FileNotFoundError:
        return False  # Key doesn't exist = enabled by default
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read registry: {e}")
        return False

def set_admin_share_status(disable=True):
    """
    Sets the AutoShareWks value.
    disable=True will set it to 0 (disable default shares).
    disable=False will set it to 1 (enable default shares).
    """
    try:
        reg = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(reg, "AutoShareWks", 0, winreg.REG_DWORD, 0 if disable else 1)
        winreg.CloseKey(reg)
        return True
    except PermissionError:
        messagebox.showerror("Permission Denied", "Admin privileges are required.")
        return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to write to registry: {e}")
        return False
