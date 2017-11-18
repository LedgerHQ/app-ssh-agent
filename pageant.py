from paramiko import win_pageant
from ctypes import windll, Structure, sizeof, WINFUNCTYPE, pointer, byref, c_uint, c_int, c_char
from ctypes.wintypes import HWND, HANDLE, HBRUSH, LPCWSTR, WPARAM, LPARAM, MSG, RECT

kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32

WS_EX_APPWINDOW = 0x40000
WS_OVERLAPPEDWINDOW = 0xcf0000
WS_CAPTION = 0xc00000
SW_SHOWNORMAL = 1
SW_SHOW = 5
CS_HREDRAW = 2
CS_VREDRAW = 1
CW_USEDEFAULT = 0x80000000
WM_PAINT = 0xF
WM_DESTROY = 0x2
WHITE_BRUSH = 0
DT_SINGLELINE = 0x20
DT_CENTER = 0x1
DT_VCENTER = 0x4

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
                ('rgbReserved', c_char * 32)]


def PyWndProcedure(hwnd, message, wParam, lParam):
    if message == WM_PAINT:
        ps = PAINTSTRUCT()
        rect = RECT()
        hdc = user32.BeginPaint(hwnd, byref(ps))
        user32.GetClientRect(hwnd, byref(rect))
        user32.DrawTextW(hdc, u"Ledger SSH Agent", -1, byref(rect), DT_SINGLELINE | DT_CENTER | DT_VCENTER)
        user32.EndPaint(hwnd, byref(ps))
        return 0;
    elif message == WM_DESTROY:
        user32.PostQuitMessage(0)
    elif message == win_pageant.win32con_WM_COPYDATA:
        pass
    else:
        return user32.DefWindowProcW(hwnd, message, wParam, lParam)
    return 0


WndProc = WNDPROCTYPE(PyWndProcedure)

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

hwnd = user32.CreateWindowExW(0,
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
user32.ShowWindow(hwnd, SW_SHOW)
user32.UpdateWindow(hwnd)

msg = MSG()
lpmsg = pointer(msg)

while user32.GetMessageW(byref(msg), 0, 0, 0) != 0:
    user32.TranslateMessage(byref(msg))
    user32.DispatchMessageW(byref(msg))
