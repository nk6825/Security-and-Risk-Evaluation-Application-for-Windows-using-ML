import zxcvbn
import platform
import winreg
import win32com.client


def rate_password_strength(password):
    result = zxcvbn.zxcvbn(password)
    return result['score']


def windows_update_status():
    # Get the Windows version
    version_info = platform.version()
    major_version = int(version_info.split('.')[0])

    # Check if the operating system is Windows 11 or newer
    if major_version >= 10:
        # Check for the presence of specific update keys
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages')
            winreg.CloseKey(reg_key)
            return True  # Windows is updated
        except FileNotFoundError:
            return False  # Windows is not updated

    return False  # Windows is not Windows 11 or newer


def firewall_status():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile')
        value, _ = winreg.QueryValueEx(key, 'EnableFirewall')
        if value == 1:
            return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print("Error occurred: {}".format(e))
        return False


def malware_count():
    malware_count = 0

    try:
        defender = win32com.client.Dispatch("Microsoft.Update.Session")
        update_searcher = defender.CreateUpdateSearcher()
        updates = update_searcher.Search("IsInstalled=0")
        update_count = updates.Updates.Count

        for i in range(update_count):
            update = updates.Updates.Item(i)
            if "Windows Defender" in update.Title:
                malware_count = update.MaxDownloadSize

    except Exception as e:
        print("Error:", str(e))

    return malware_count


def uac_status():
    try:
        uac_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        uac_value, _ = winreg.QueryValueEx(uac_key, "EnableLUA")
        if uac_value == 1:
            return True

    except FileNotFoundError:
        return False

    except Exception as e:
        print("Error:", str(e))
        return False


def sum(a, b, c, d, e, f):
    return a + b + c + d + e + f
