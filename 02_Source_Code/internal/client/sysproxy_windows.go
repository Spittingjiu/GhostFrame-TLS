//go:build windows

package client

import (
	"syscall"
	"unsafe"
)

var (
	modWininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modWininet.NewProc("InternetSetOptionW")

	modAdvapi32       = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx  = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey   = modAdvapi32.NewProc("RegCloseKey")
	procRegSetValueEx = modAdvapi32.NewProc("RegSetValueExW")
	procRegQueryValue = modAdvapi32.NewProc("RegQueryValueExW")
)

const (
	hkeyCurrentUser = 0x80000001

	keyQueryValue = 0x0001
	keySetValue   = 0x0002

	regSz    = 1
	regDword = 4

	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

func refreshSysProxy() {
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// SetSystemProxy sets or unsets the Windows Internet Settings system proxy.
func SetSystemProxy(addr string, enable bool) error {
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue|keyQueryValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	valNameServer, _ := syscall.UTF16PtrFromString("ProxyServer")
	valNameOverride, _ := syscall.UTF16PtrFromString("ProxyOverride")

	var enableDword uint32
	if enable {
		enableDword = 1
	}

	procRegSetValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameEnable)),
		0,
		uintptr(regDword),
		uintptr(unsafe.Pointer(&enableDword)),
		4,
	)

	if enable && addr != "" {
		serverBytes, _ := syscall.UTF16FromString(addr)
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(valNameServer)),
			0,
			uintptr(regSz),
			uintptr(unsafe.Pointer(&serverBytes[0])),
			uintptr(len(serverBytes)*2),
		)

		overrideBytes, _ := syscall.UTF16FromString("localhost;127.*;10.*;172.16.*;192.168.*;<local>")
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(valNameOverride)),
			0,
			uintptr(regSz),
			uintptr(unsafe.Pointer(&overrideBytes[0])),
			uintptr(len(overrideBytes)*2),
		)
	}

	refreshSysProxy()
	return nil
}

// GetSystemProxy returns current system proxy settings.
func GetSystemProxy() (enabled bool, server string, err error) {
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return false, "", err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keyQueryValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return false, "", err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var valType, enableDword, valLen uint32
	valLen = 4
	r1, _, _ = procRegQueryValue.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameEnable)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&enableDword)),
		uintptr(unsafe.Pointer(&valLen)),
	)
	if r1 == 0 && enableDword == 1 {
		enabled = true
	}

	valNameServer, _ := syscall.UTF16PtrFromString("ProxyServer")
	var buf [256]uint16
	valLen = uint32(len(buf) * 2)
	r1, _, _ = procRegQueryValue.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameServer)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&valLen)),
	)
	if r1 == 0 {
		server = syscall.UTF16ToString(buf[:])
	}
	return enabled, server, nil
}
