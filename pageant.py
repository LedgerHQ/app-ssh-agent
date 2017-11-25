from base64 import b64encode
from ctypes import windll, Structure, sizeof, WINFUNCTYPE, pointer, byref, c_uint, c_int, c_char, c_wchar, memmove
from ctypes.wintypes import HWND, HANDLE, HBRUSH, LPCWSTR, WPARAM, LPARAM, MSG, RECT, HICON, POINT, DWORD, WORD, ARRAY
from struct import pack

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from paramiko import win_pageant
from pkg_resources import resource_stream

kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32
shell32 = windll.shell32
comctl32 = windll.comctl32

WS_EX_APPWINDOW = 0x40000
WS_OVERLAPPEDWINDOW = 0xcf0000
WS_CAPTION = 0xc00000
SW_SHOWNORMAL = 1
SW_SHOW = 5
SW_HIDE = 0
CS_HREDRAW = 2
CS_VREDRAW = 1
CW_USEDEFAULT = 0x80000000
WM_PAINT = 0xF
WM_DESTROY = 0x2
WHITE_BRUSH = 0
DT_SINGLELINE = 0x20
DT_CENTER = 0x1
DT_VCENTER = 0x4
MF_BYPOSITION = 1024
MF_STRING = 0
MF_SEPARATOR = 2048
TPM_LEFTALIGN = 0
TPM_RIGHTBUTTON = 2
TPM_RETURNCMD = 256
TPM_NONOTIFY = 128
WM_CREATE = 1
WM_COMMAND = 273
WM_QUIT = 18
WM_APP = 32768
WM_MOUSEMOVE = 512
WM_LBUTTONUP = 514
WM_MBUTTONUP = 520
WM_RBUTTONUP = 517
WM_LBUTTONDBLCLK = 515
NIM_ADD = 0
NIM_DELETE = 2
NIM_MODIFY = 1
NIM_SETVERSION = 4
CF_TEXT = 1
GMEM_MOVEABLE = 2
GMEM_ZEROINIT = 64
GHND = (GMEM_MOVEABLE | GMEM_ZEROINIT)

WNDPROCTYPE = WINFUNCTYPE(c_int, HWND, c_uint, WPARAM, LPARAM)


class WNDCLASSEX(Structure):
    _fields_ = [("cbSize", c_uint),
                ("style", c_uint),
                ("lpfnWndProc", WNDPROCTYPE),
                ("cbClsExtra", c_int),
                ("cbWndExtra", c_int),
                ("hInstance", HANDLE),
                ("hIcon", HANDLE),
                ("hCursor", HANDLE),
                ("hBrush", HBRUSH),
                ("lpszMenuName", LPCWSTR),
                ("lpszClassName", LPCWSTR),
                ("hIconSm", HANDLE),
                ]


class PAINTSTRUCT(Structure):
    _fields_ = [('hdc', c_int),
                ('fErase', c_int),
                ('rcPaint', RECT),
                ('fRestore', c_int),
                ('fIncUpdate', c_int),
                ('rgbReserved', ARRAY(c_char, 32)),
                ]


class GUID(Structure):
    _fields_ = [('Data1', DWORD),
                ('Data2', WORD),
                ('Data3', WORD),
                ('Data4', ARRAY(c_char, 8)),
                ]


class NOTIFYICONDATA(Structure):
    _fields_ = [('cbSize', DWORD),
                ('hWnd', HWND),
                ('uID', c_uint),
                ('uFlags', c_uint),
                ('uCallbackMessage', c_uint),
                ('hIcon', HICON),
                ('szTip', ARRAY(c_wchar, 128)),
                ('dwState', DWORD),
                ('dwStateMask', DWORD),
                ('szInfo', ARRAY(c_wchar, 256)),
                ('uVersion', c_uint),
                ('szInfoTitle', ARRAY(c_wchar, 64)),
                ('dwInfoFlags', DWORD),
                ('guidItem', GUID),
                ('hBalloonIcon', HICON),
                ]


user32.DefWindowProcW.argtypes = [HWND, c_uint, WPARAM, LPARAM]

ID_EXIT = 2000
ID_PUBLIC = 2001


def get_icon_bytes():
    with resource_stream(__name__, 'ledger.ico') as f:
        return f.read()


def show_popup_menu(hwnd):
    hide_popup_menu()
    menu = user32.CreatePopupMenu()
    user32.InsertMenuW(menu, 0, MF_BYPOSITION | MF_STRING, ID_PUBLIC, u'Get Public Key')
    user32.InsertMenuW(menu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, None)
    user32.InsertMenuW(menu, 2, MF_BYPOSITION | MF_STRING, ID_EXIT, u'Exit')
    user32.SetMenuDefaultItem(menu, ID_PUBLIC, False)
    user32.SetFocus(hwnd)
    user32.SetForegroundWindow(hwnd)

    pt = POINT()
    user32.GetCursorPos(byref(pt))
    cmd = user32.TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, None)
    user32.SendMessageA(hwnd, WM_COMMAND, cmd, 0)
    user32.DestroyMenu(menu)


def hide_popup_menu():
    hwnd = user32.FindWindowExW(None, None, LPCWSTR(0x8000), None)
    if hwnd != 0:
        user32.DestroyWindow(hwnd)


def stop(hwnd):
    if not hwnd:
        return

    nid = NOTIFYICONDATA()
    nid.cbSize = sizeof(NOTIFYICONDATA)
    nid.hWnd = hwnd
    nid.uId = 1
    shell32.Shell_NotifyIcon(NIM_DELETE, byref(nid))
    user32.SendMessageA(hwnd, WM_QUIT, 0, 0)


CURVE_NAME = "nistp256"
KEY_HEADER = "ecdsa-sha2-nistp256"
KEY_PATH = "44'/535348'/0'/0/0"
TIMEOUT_SECONDS = 5


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + pack(">I", int(element[0]))
        else:
            result = result + pack(">I", 0x80000000 | int(element[0]))
    return result


def get_public_key():
    p2 = "01"
    key_header = KEY_HEADER
    dongle_path = parse_bip32_path(KEY_PATH)
    apdu = "800200" + p2
    apdu = apdu.decode('hex') + chr(len(dongle_path) + 1) + chr(len(dongle_path) / 4) + dongle_path
    try:
        dongle = getDongle(False)
    except CommException as e:
        return e.message
    try:
        result = dongle.exchange(bytes(apdu), TIMEOUT_SECONDS)
    except CommException as e:
        return e.message
    finally:
        dongle.close()
    key = str(result[1:])
    blob = pack(">I", len(KEY_HEADER)) + key_header
    blob += pack(">I", len(CURVE_NAME)) + CURVE_NAME
    blob += pack(">I", len(key)) + key
    return key_header + " " + b64encode(blob)


def copy_public_key_to_clipboard(hwnd):
    public_key = get_public_key()
    user32.OpenClipboard(hwnd)
    user32.EmptyClipboard()
    handle = kernel32.GlobalAlloc(GHND, len(public_key) + 1)
    locked = kernel32.GlobalLock(handle)
    memmove(locked, public_key, len(public_key))
    kernel32.GlobalUnlock(handle)
    user32.SetClipboardData(CF_TEXT, handle)
    user32.CloseClipboard()


def wnd_procedure(hwnd, message, w_param, l_param):
    if message == WM_PAINT:
        ps = PAINTSTRUCT()
        rect = RECT()
        hdc = user32.BeginPaint(hwnd, byref(ps))
        user32.GetClientRect(hwnd, byref(rect))
        user32.DrawTextW(hdc, u"Ledger SSH Agent", -1, byref(rect), DT_SINGLELINE | DT_CENTER | DT_VCENTER)
        user32.EndPaint(hwnd, byref(ps))
    elif message == WM_DESTROY:
        user32.PostQuitMessage(0)
    elif message == WM_QUIT:
        user32.PostQuitMessage(0)
    elif message == WM_CREATE:
        icon_bytes = get_icon_bytes()
        icon_index = user32.LookupIconIdFromDirectory(icon_bytes, True)
        icon = user32.CreateIconFromResource(icon_bytes[icon_index:], len(icon_bytes) - icon_index, True, 0x00030000)
        nid = NOTIFYICONDATA()
        nid.cbSize = sizeof(NOTIFYICONDATA)
        nid.hWnd = hwnd
        nid.uId = 1
        nid.uFlags = 1 | 2 | 4
        nid.szTip = u"Ledger SSH Agent"
        nid.uCallbackMessage = WM_APP
        nid.hIcon = icon
        shell32.Shell_NotifyIconW(NIM_ADD, byref(nid))
    elif message == WM_APP:
        if l_param == WM_RBUTTONUP:
            show_popup_menu(hwnd)
        elif l_param != WM_MOUSEMOVE:
            hide_popup_menu()
    elif message == WM_COMMAND:
        if w_param == ID_PUBLIC:
            copy_public_key_to_clipboard(hwnd)
        elif w_param == ID_EXIT:
            stop(hwnd)
    elif message == win_pageant.win32con_WM_COPYDATA:
        pass
    else:
        return user32.DefWindowProcW(hwnd, message, w_param, l_param)
    return 0


WndProc = WNDPROCTYPE(wnd_procedure)

hInst = kernel32.GetModuleHandleW(0)

szAppName = u"Pageant"
wndclass = WNDCLASSEX()
wndclass.cbSize = sizeof(WNDCLASSEX)
wndclass.style = CS_HREDRAW | CS_VREDRAW
wndclass.lpfnWndProc = WndProc
wndclass.cbClsExtra = 0
wndclass.cbWndExtra = 0
wndclass.hInstance = hInst
wndclass.hIcon = 0
wndclass.hCursor = 0
wndclass.hBrush = gdi32.GetStockObject(WHITE_BRUSH)
wndclass.lpszMenuName = 0
wndclass.lpszClassName = szAppName
wndclass.hIconSm = 0

hr_registerclass = user32.RegisterClassExW(byref(wndclass))

main = user32.CreateWindowExW(0,
                              szAppName,
                              szAppName,
                              WS_OVERLAPPEDWINDOW | WS_CAPTION,
                              CW_USEDEFAULT,
                              CW_USEDEFAULT,
                              CW_USEDEFAULT,
                              CW_USEDEFAULT,
                              0,
                              0,
                              hInst,
                              0)
user32.ShowWindow(main, SW_HIDE)
user32.UpdateWindow(main)

msg = MSG()
lpmsg = pointer(msg)

while user32.GetMessageW(byref(msg), 0, 0, 0) != 0:
    user32.TranslateMessage(byref(msg))
    user32.DispatchMessageW(byref(msg))
