//go:build !windows

package client

// SetSystemProxy stub for non-Windows platforms.
func SetSystemProxy(addr string, enable bool) error { return nil }

// GetSystemProxy stub for non-Windows platforms.
func GetSystemProxy() (bool, string, error)         { return false, "", nil }
