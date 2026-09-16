//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOpenCodexDeviceFileRepairsLegacyUnmappedSID(t *testing.T) {
	path := newWindowsDeviceCredentialTestFile(t)
	user := currentWindowsTestUser(t)
	stale, err := windows.StringToSid("S-1-5-21-4294967294-4294967293-4294967292-4294967291")
	if err != nil {
		t.Fatal(err)
	}
	setWindowsTestDACL(t, path, []windows.EXPLICIT_ACCESS{
		windowsTestACE(user, windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
		windowsTestACE(stale, windows.ACCESS_MASK(codexWindowsLegacyStaleSIDMask), windows.TRUSTEE_IS_UNKNOWN),
	})

	file, err := openCodexDeviceFileNoFollow(path)
	if err != nil {
		t.Fatalf("repairing legacy device credential ACL: %v", err)
	}
	defer file.Close()
	repairedHandle := windows.Handle(file.Fd())
	ownerCurrent, _, aclSafe, err := codexWindowsHandleSecurityForPolicy(repairedHandle, codexWindowsACLPolicyDeviceCredential)
	if err != nil || !ownerCurrent || !aclSafe {
		t.Fatalf("repaired ACL state: ownerCurrent=%v aclSafe=%v err=%v", ownerCurrent, aclSafe, err)
	}
	sd, err := windows.GetSecurityInfo(repairedHandle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("repaired ACL is not protected: control=%#x err=%v", control, err)
	}
	if sandbox, lookupErr := codexWindowsLocalSandboxSID(); lookupErr == nil {
		assertWindowsSandboxReadOnlyACE(t, sd, sandbox)
	}
}

func TestOpenCodexDeviceFileRejectsResolvableUntrustedWriter(t *testing.T) {
	path := newWindowsDeviceCredentialTestFile(t)
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsTestDACL(t, path, []windows.EXPLICIT_ACCESS{
		windowsTestACE(currentWindowsTestUser(t), windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
		windowsTestACE(everyone, windows.GENERIC_ALL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	})
	if file, err := openCodexDeviceFileNoFollow(path); err == nil {
		file.Close()
		t.Fatal("device credential with Everyone full control was accepted")
	}
}

func TestOpenCodexDeviceFileRejectsSandboxWrite(t *testing.T) {
	sandbox, err := codexWindowsLocalSandboxSID()
	if err != nil {
		t.Skipf("local Codex sandbox group is unavailable: %v", err)
	}
	path := newWindowsDeviceCredentialTestFile(t)
	setWindowsTestDACL(t, path, []windows.EXPLICIT_ACCESS{
		windowsTestACE(currentWindowsTestUser(t), windows.GENERIC_ALL, windows.TRUSTEE_IS_USER),
		windowsTestACE(sandbox, windows.GENERIC_WRITE, windows.TRUSTEE_IS_GROUP),
	})
	if file, err := openCodexDeviceFileNoFollow(path); err == nil {
		file.Close()
		t.Fatal("device credential granting sandbox write access was accepted")
	}
}

func newWindowsDeviceCredentialTestFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"tokens":{"access_token":"test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func currentWindowsTestUser(t *testing.T) *windows.SID {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func windowsTestACE(sid *windows.SID, permissions windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func setWindowsTestDACL(t *testing.T, path string, entries []windows.EXPLICIT_ACCESS) {
	t.Helper()
	handle := openWindowsTestFile(t, path, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC)
	defer windows.CloseHandle(handle)
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func openWindowsTestFile(t *testing.T, path string, access uint32) windows.Handle {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, codexWindowsNoFollowOpenFlags(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func assertWindowsSandboxReadOnlyACE(t *testing.T, sd *windows.SECURITY_DESCRIPTOR, sandbox *windows.SID) {
	t.Helper()
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("repaired DACL unavailable: %v", err)
	}
	header := (*codexWindowsACLHeader)(unsafe.Pointer(dacl))
	for index := uint32(0); index < uint32(header.count); index++ {
		var raw *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &raw); err != nil || raw == nil {
			t.Fatalf("reading repaired ACE %d: %v", index, err)
		}
		prefix := (*codexWindowsACEPrefix)(unsafe.Pointer(raw))
		if prefix.header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&raw.SidStart))
		if sid.IsValid() && sid.Equals(sandbox) {
			mask := uint32(prefix.mask)
			if mask&codexWindowsMutationMask != 0 || mask&codexWindowsReadData == 0 || mask&codexWindowsReadControl == 0 {
				t.Fatalf("sandbox ACE mask = %#x, want mapped read-only rights", mask)
			}
			return
		}
	}
	t.Fatal("local CodexSandboxUsers read ACE is missing")
}
