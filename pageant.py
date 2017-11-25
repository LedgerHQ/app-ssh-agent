from base64 import b64encode, b64decode
from ctypes import addressof, c_ubyte, create_string_buffer, c_size_t
from ctypes import c_void_p, c_long, c_longlong, c_ulong, c_ulonglong, POINTER, cast, string_at
from ctypes import windll, Structure, sizeof, WINFUNCTYPE, pointer, byref, c_uint, c_int, c_char, c_wchar, memmove
from ctypes.wintypes import BOOL, USHORT, LPWSTR
from ctypes.wintypes import HWND, HANDLE, HBRUSH, LPCWSTR, WPARAM, LPARAM, MSG, RECT, HICON, POINT, DWORD, WORD, ARRAY
from struct import pack, unpack
from sys import maxint

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from pkg_resources import resource_stream

kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32
shell32 = windll.shell32
comctl32 = windll.comctl32
advapi32 = windll.advapi32

CreateFileMapping = kernel32.CreateFileMappingW
CreateFileMapping.argtypes = [
    HANDLE,
    c_void_p,
    DWORD,
    DWORD,
    DWORD,
    LPWSTR,
]
CreateFileMapping.restype = HANDLE

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
WM_COPYDATA = 74
AGENT_COPYDATA_ID = 0x804e50ba
AGENT_MAX_MSGLEN = 8192
INVALID_HANDLE_VALUE = -1
PAGE_READWRITE = 0x4
FILE_MAP_WRITE = 0x2
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5

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


PVOID = c_void_p
if sizeof(c_long) == sizeof(c_void_p):
    ULONG_PTR = c_ulong
    LONG_PTR = c_long
elif sizeof(c_longlong) == sizeof(c_void_p):
    ULONG_PTR = c_ulonglong
    LONG_PTR = c_longlong


class COPYDATASTRUCT(Structure):
    _fields_ = [('dwData', ULONG_PTR),
                ('cbData', DWORD),
                ('lpData', PVOID),
                ]


PCOPYDATASTRUCT = POINTER(COPYDATASTRUCT)


class TokenAccess:
    def __init__(self):
        pass

    TOKEN_QUERY = 0x8


class TokenInformationClass:
    def __init__(self):
        pass

    TokenUser = 1


class TokenUser(Structure):
    num = 1
    _fields_ = [('SID', c_void_p),
                ('ATTRIBUTES', DWORD),
                ]


class SecurityDescriptor(Structure):
    SECURITY_DESCRIPTOR_CONTROL = USHORT
    REVISION = 1
    _fields_ = [('Revision', c_ubyte),
                ('Sbz1', c_ubyte),
                ('Control', SECURITY_DESCRIPTOR_CONTROL),
                ('Owner', c_void_p),
                ('Group', c_void_p),
                ('Sacl', c_void_p),
                ('Dacl', c_void_p),
                ]


class SecurityAttributes(Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', c_void_p),
                ('bInheritHandle', BOOL),
                ]

    def __init__(self, *args, **kwargs):
        super(SecurityAttributes, self).__init__(*args, **kwargs)
        self.nLength = sizeof(SecurityAttributes)
        self._descriptor = None
        self.lpSecurityDescriptor = None

    @property
    def descriptor(self):
        return self._descriptor

    @descriptor.setter
    def descriptor(self, value):
        self._descriptor = value
        self.lpSecurityDescriptor = addressof(value)


advapi32.SetSecurityDescriptorOwner.argtypes = (
    POINTER(SecurityDescriptor),
    c_void_p,
    BOOL,
)


def get_token_information(token, information_class):
    data_size = DWORD()
    advapi32.GetTokenInformation(token, information_class.num, 0, 0, byref(data_size))
    data = create_string_buffer(data_size.value)
    advapi32.GetTokenInformation(token,
                                 information_class.num,
                                 byref(data), sizeof(data),
                                 byref(data_size))
    return cast(data, POINTER(TokenUser)).contents


def open_process_token(proc_handle, access):
    result = HANDLE()
    proc_handle = HANDLE(proc_handle)
    advapi32.OpenProcessToken(proc_handle, access, byref(result))
    return result


def get_current_user():
    process = open_process_token(kernel32.GetCurrentProcess(), TokenAccess.TOKEN_QUERY)
    return get_token_information(process, TokenUser)


def get_security_attributes_for_user(user=None):
    if user is None:
        user = get_current_user()
    assert isinstance(user, TokenUser), "user must be TOKEN_USER instance"
    security_descriptor = SecurityDescriptor()
    security_attributes = SecurityAttributes()
    security_attributes.descriptor = security_descriptor
    security_attributes.bInheritHandle = 1
    advapi32.InitializeSecurityDescriptor(byref(security_descriptor), SecurityDescriptor.REVISION)
    advapi32.SetSecurityDescriptorOwner(byref(security_descriptor), user.SID, 0)
    return security_attributes


security_attributes_global = get_security_attributes_for_user()
security_attributes_pointer = (
    byref(security_attributes_global)
    if security_attributes_global else None
)


class MemoryMap(object):
    def __init__(self, name):
        self.filemap = INVALID_HANDLE_VALUE
        self.length = AGENT_MAX_MSGLEN
        self.name = name
        self.pos = 0

    def __enter__(self):
        self.filemap = CreateFileMapping(INVALID_HANDLE_VALUE, security_attributes_pointer, PAGE_READWRITE, 0,
                                         self.length, self.name)
        if self.filemap == INVALID_HANDLE_VALUE:
            raise Exception("Failed to create file mapping")
        self.view = kernel32.MapViewOfFile(self.filemap, FILE_MAP_WRITE, 0, 0, 0)
        return self

    def seek(self, pos):
        self.pos = pos

    def write(self, data):
        assert isinstance(data, bytes)
        n = len(data)
        if self.pos + n >= self.length:
            raise ValueError("Refusing to write %d bytes" % n)
        dest = self.view + self.pos
        length = c_size_t(n)
        kernel32.RtlMoveMemory(dest, data, length)
        self.pos += n

    def read(self, n):
        out = create_string_buffer(n)
        source = self.view + self.pos
        length = c_size_t(n)
        kernel32.RtlMoveMemory(out, source, length)
        self.pos += n
        return out.raw

    def __exit__(self, exc_type, exc_val, tb):
        kernel32.UnmapViewOfFile(self.view)
        kernel32.CloseHandle(self.filemap)


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


def get_public_key(timeout=TIMEOUT_SECONDS):
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
        result = dongle.exchange(bytes(apdu), timeout)
    except CommException as e:
        return e.message
    finally:
        dongle.close()
    key = str(result[1:])
    blob = pack(">I", len(KEY_HEADER)) + key_header
    blob += pack(">I", len(CURVE_NAME)) + CURVE_NAME
    blob += pack(">I", len(key)) + key
    return key_header + " " + b64encode(blob)


public_key_global = get_public_key(maxint)
if ' ' not in public_key_global:
    raise Exception('Public key reading error: %s' % public_key_global)
key_blob = b64decode(public_key_global.split(' ', 1)[1])


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


def read_file_name_from_input(l_param):
    cds = cast(l_param, PCOPYDATASTRUCT)
    map_name = string_at(cds.contents.lpData)
    return map_name


def process_keys_request(pymap):
    response = chr(SSH2_AGENT_IDENTITIES_ANSWER)
    response += pack(">I", 1)
    response += pack(">I", len(key_blob)) + key_blob
    response += pack(">I", len(KEY_PATH)) + KEY_PATH
    agent_response = pack(">I", len(response)) + response
    pymap.seek(0)
    pymap.write(agent_response)


def process_sign_request(pymap):
    datalen = pymap.read(4)
    blob_size = unpack(">I", datalen)[0]
    blob = pymap.read(blob_size)
    if blob != key_blob:
        print ("Client sent a different blob " + blob.encode('hex'))
        response = chr(SSH_AGENT_FAILURE)
        agent_response = pack(">I", len(response)) + response
        pymap.seek(0)
        pymap.write(agent_response)
    challenge_size = unpack(">I", pymap.read(4))[0]
    challenge = pymap.read(challenge_size)
    dongle = getDongle(False)
    offset = 0
    signature = None
    while offset != len(challenge):
        data = ""
        if offset == 0:
            dongle_path = parse_bip32_path(KEY_PATH)
            data = chr(len(dongle_path) / 4) + dongle_path
        if (len(challenge) - offset) > (255 - len(data)):
            chunk_size = (255 - len(data))
        else:
            chunk_size = len(challenge) - offset
        data += challenge[offset: offset + chunk_size]
        if offset == 0:
            p1 = 0x00
        else:
            p1 = 0x01
        p2 = 0x01
        offset += chunk_size
        apdu = "8004".decode('hex') + chr(p1) + chr(p2) + chr(len(data)) + data
        signature = dongle.exchange(bytes(apdu))
    dongle.close()
    length = signature[3]
    r = signature[4: 4 + length]
    s = signature[4 + length + 2:]
    r = str(r)
    s = str(s)
    encoded_signature_value = pack(">I", len(r)) + r
    encoded_signature_value += pack(">I", len(s)) + s
    encoded_signature = pack(">I", len(KEY_HEADER)) + KEY_HEADER
    encoded_signature += pack(">I", len(encoded_signature_value)) + encoded_signature_value
    response = chr(SSH2_AGENT_SIGN_RESPONSE)
    response += pack(">I", len(encoded_signature)) + encoded_signature
    agent_response = pack(">I", len(response)) + response
    pymap.seek(0)
    pymap.write(agent_response)


def answer_if_device_present(pymap):
    pymap.seek(0)
    datalen = pymap.read(4)
    retlen = unpack('>I', datalen)[0]
    if retlen > 1:
        retlen = 1
    request_type = ord(pymap.read(retlen))
    if request_type == SSH2_AGENTC_REQUEST_IDENTITIES:
        process_keys_request(pymap)
        return 1
    elif request_type == SSH2_AGENTC_SIGN_REQUEST:
        process_sign_request(pymap)
        return 1
    else:
        pymap.seek(0)
        response = chr(SSH_AGENT_FAILURE)
        agent_response = pack(">I", len(response)) + response
        pymap.seek(0)
        pymap.write(agent_response)
        return 0


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
    elif message == WM_COPYDATA:
        map_name = read_file_name_from_input(l_param)
        pymap = MemoryMap(map_name)
        with pymap:
            ret = answer_if_device_present(pymap)
        return ret
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
