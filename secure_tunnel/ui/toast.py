"""
Windows balloon-tip notification via Win32 Shell_NotifyIcon API.

Usage:
    from secure_tunnel.ui.toast import notify
    notify("SecureTunnel", "Туннель запущен!")
"""


def notify(title: str, message: str, has_tray: bool = True) -> None:
    """
    Show a Windows balloon-tip notification via Shell_NotifyIconW.
    Falls back silently on any error (non-admin, no tray, etc.).

    Parameters
    ----------
    title    : notification title (max 63 chars)
    message  : notification body (max 255 chars)
    has_tray : pass False to skip immediately (tray not available)
    """
    if not has_tray:
        return
    try:
        import ctypes
        from ctypes import wintypes

        NIM_MODIFY = 0x00000001
        NIF_INFO   = 0x00000010
        NIIF_INFO  = 0x00000001

        class NOTIFYICONDATA(ctypes.Structure):
            _fields_ = [
                ("cbSize",           wintypes.DWORD),
                ("hWnd",             wintypes.HWND),
                ("uID",              wintypes.UINT),
                ("uFlags",           wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon",            wintypes.HANDLE),
                ("szTip",            ctypes.c_wchar * 128),
                ("dwState",          wintypes.DWORD),
                ("dwStateMask",      wintypes.DWORD),
                ("szInfo",           ctypes.c_wchar * 256),
                ("uTimeout",         wintypes.UINT),
                ("szInfoTitle",      ctypes.c_wchar * 64),
                ("dwInfoFlags",      wintypes.DWORD),
            ]

        nid = NOTIFYICONDATA()
        nid.cbSize      = ctypes.sizeof(NOTIFYICONDATA)
        nid.uFlags      = NIF_INFO
        nid.szInfo      = message[:255]
        nid.szInfoTitle = title[:63]
        nid.dwInfoFlags = NIIF_INFO
        nid.uTimeout    = 5000
        ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
    except Exception:
        pass
