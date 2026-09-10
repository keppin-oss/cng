//go:build windows

package windowscng

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestCNGFlagConstants(t *testing.T) {
	tests := []struct {
		name      string
		got, want uint32
	}{
		{"ncryptMachineKeyFlag", ncryptMachineKeyFlag, 0x00000020},
		{"ncryptSilentFlag", ncryptSilentFlag, 0x00000040},
		{"ncryptAllowSigningFlag", ncryptAllowSigningFlag, 0x00000001},
		{"ncryptAllowExportFlag", ncryptAllowExportFlag, 0x00000001},
		{"ncryptAllowPlaintextExportFlag", ncryptAllowPlaintextExportFlag, 0x00000002},
		{"ncryptAllowArchivingFlag", ncryptAllowArchivingFlag, 0x00000004},
		{"ncryptAllowPlaintextArchivingFlag", ncryptAllowPlaintextArchivingFlag, 0x00000008},
		{"daclSecurityInformation", daclSecurityInformation, 0x00000004},
		{"genericAll", genericAll, 0x10000000},
		{"genericRead", genericRead, 0x80000000},
		{"genericWrite", genericWrite, 0x40000000},
		{"genericExecute", genericExecute, 0x20000000},
		{"genericRights", genericRights, 0xF0000000},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = 0x%08X, want 0x%08X", tt.name, tt.got, tt.want)
		}
	}
}

const ncryptCreatePersistedKeyValidMask = 0x000007E0

func TestNCryptCreatePersistedKeyValidFlags(t *testing.T) {
	var createFlags uint32 = ncryptMachineKeyFlag
	if createFlags&^uint32(ncryptCreatePersistedKeyValidMask) != 0 {
		t.Errorf("NCryptCreatePersistedKey flags 0x%08X contain undocumented bits", createFlags)
	}
	if createFlags&ncryptAllowSigningFlag != 0 {
		t.Error("NCRYPT_ALLOW_SIGNING_FLAG is a key-usage property value, not a creation flag")
	}
	if createFlags&ncryptSilentFlag != 0 {
		t.Error("NCRYPT_SILENT_FLAG is not valid for NCryptCreatePersistedKey")
	}
}

func TestNCryptOpenKeyValidFlags(t *testing.T) {
	var openFlags uint32 = openKeyFlags
	const valid = ncryptMachineKeyFlag | ncryptSilentFlag
	if openFlags&^uint32(valid) != 0 {
		t.Errorf("NCryptOpenKey flags 0x%08X contain undocumented bits", openFlags)
	}
}

func TestNCryptDeleteOpenFlags(t *testing.T) {
	if deleteKeyOpenFlags != 0x00000060 {
		t.Errorf("deleteKeyOpenFlags = 0x%08X, want 0x00000060 (machine|silent)", deleteKeyOpenFlags)
	}
	if deleteKeyOpenFlags&ncryptMachineKeyFlag == 0 {
		t.Error("deleteKeyOpenFlags must include NCRYPT_MACHINE_KEY_FLAG")
	}
	if deleteKeyOpenFlags&ncryptSilentFlag == 0 {
		t.Error("deleteKeyOpenFlags must include NCRYPT_SILENT_FLAG")
	}
	if deleteKeyOpenFlags&^uint32(ncryptMachineKeyFlag|ncryptSilentFlag) != 0 {
		t.Error("deleteKeyOpenFlags must not contain any undocumented bits")
	}
}

func TestNCryptSecurityDescrFlags(t *testing.T) {
	if daclSecurityInformation&ncryptSilentFlag != 0 {
		t.Fatalf("DACL_SECURITY_INFORMATION must not collide with NCRYPT_SILENT_FLAG in the value used here")
	}
	if daclSecurityInformation != 0x00000004 {
		t.Fatalf("DACL_SECURITY_INFORMATION = 0x%08X, want 0x00000004", daclSecurityInformation)
	}
}

func TestGenericAllIsOwnBit(t *testing.T) {
	if genericAll == genericRights {
		t.Fatal("GENERIC_ALL is a single bit, not the extraction mask")
	}
	if genericAll&(genericRead|genericWrite|genericExecute) != 0 {
		t.Fatal("GENERIC_ALL must be distinct from READ/WRITE/EXECUTE")
	}
}

func TestLocalServiceStaticMaskSemantics(t *testing.T) {
	// The static verifier proves the principal boundary. It must not infer
	// signing capability from a serialized GENERIC_EXECUTE bit because the
	// Microsoft Software KSP canonicalized the real persisted LS ACE to GR.
	lsStaticValid := func(mask uint32) bool {
		generic := mask & genericRights
		return generic&genericRead != 0 && generic&genericWrite == 0 && generic&genericAll == 0
	}

	if !lsStaticValid(0x80000000) {
		t.Error("persisted LOCAL SERVICE GR-only mask from manual proof must pass static boundary validation")
	}
	if !lsStaticValid(0xA0000000) {
		t.Error("GR|GX must also pass static boundary validation")
	}
	if lsStaticValid(0xC0000000) {
		t.Error("GR|GW must fail: write access is forbidden")
	}
	if lsStaticValid(0x90000000) {
		t.Error("GR|GA must fail: administrative access is forbidden")
	}
	if lsStaticValid(0x20000000) {
		t.Error("GX-only must fail: read/open capability is required")
	}
}

func TestSystemAdminStaticMaskSemantics(t *testing.T) {
	hasGenericAll := func(mask uint32) bool { return mask&genericAll != 0 }
	for _, mask := range []uint32{0x10000000, 0xD0000000, 0xF0000000} {
		if !hasGenericAll(mask) {
			t.Errorf("0x%08X should contain GENERIC_ALL", mask)
		}
	}
	for _, mask := range []uint32{0, 0x80000000, 0xA0000000, 0xC0000000} {
		if hasGenericAll(mask) {
			t.Errorf("0x%08X should not contain GENERIC_ALL", mask)
		}
	}
}

func TestACLInspectionConstants(t *testing.T) {
	if aceTypeAccessAllowed != 0 {
		t.Errorf("aceTypeAccessAllowed = %d, want 0", aceTypeAccessAllowed)
	}
	if aclSizeInfoClass != 2 {
		t.Errorf("aclSizeInfoClass = %d, want 2", aclSizeInfoClass)
	}
}

func TestWellKnownSIDStrings(t *testing.T) {
	tests := []struct{ name, got, want string }{
		{"SYSTEM", sidSYSTEM, "S-1-5-18"},
		{"Administrators", sidAdministrators, "S-1-5-32-544"},
		{"LOCAL SERVICE", sidLocalService, "S-1-5-19"},
		{"Everyone", sidEveryone, "S-1-1-0"},
		{"Authenticated Users", sidAuthUsers, "S-1-5-11"},
		{"Built-in Users", sidBuiltinUsers, "S-1-5-32-545"},
		{"Interactive", sidInteractive, "S-1-5-4"},
		{"Service", sidService, "S-1-5-6"},
		{"Anonymous", sidAnonymous, "S-1-5-7"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s SID = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

func TestBCryptECCPublicBlobConstant(t *testing.T) {
	if bcryptECCPublicBlob != "ECCPUBLICBLOB" {
		t.Errorf("bcryptECCPublicBlob = %q, want %q (per Windows SDK BCRYPT_ECCPUBLIC_BLOB)", bcryptECCPublicBlob, "ECCPUBLICBLOB")
	}
}

func TestECCPublicBlobMagicConstant(t *testing.T) {
	if ecdsaPublicBlobMagic != 0x31534345 {
		t.Errorf("ecdsaPublicBlobMagic = 0x%X, want 0x31534345 (ECS1)", ecdsaPublicBlobMagic)
	}
}

func TestKSPAndAlgorithmConstants(t *testing.T) {
	if msSoftwareKSP != "Microsoft Software Key Storage Provider" {
		t.Errorf("msSoftwareKSP = %q", msSoftwareKSP)
	}
	if ecdsaP256Algorithm != "ECDSA_P256" {
		t.Errorf("ecdsaP256Algorithm = %q, want %q", ecdsaP256Algorithm, "ECDSA_P256")
	}
}

func buildPublicBlob(x, y *big.Int) []byte {
	blob := make([]byte, 8+2*ecdsaP256CoordinateSize)
	binary.LittleEndian.PutUint32(blob[0:4], ecdsaPublicBlobMagic)
	binary.LittleEndian.PutUint32(blob[4:8], ecdsaP256CoordinateSize)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(blob[8+ecdsaP256CoordinateSize-len(xb):8+ecdsaP256CoordinateSize], xb)
	copy(blob[8+2*ecdsaP256CoordinateSize-len(yb):8+2*ecdsaP256CoordinateSize], yb)
	return blob
}

func TestParseECCPublicBlobValid(t *testing.T) {
	gx := elliptic.P256().Params().Gx
	gy := elliptic.P256().Params().Gy
	blob := buildPublicBlob(gx, gy)
	pub, err := parseECCPublicBlob(blob)
	if err != nil {
		t.Fatalf("parseECCPublicBlob: %v", err)
	}
	if pub.X.Cmp(gx) != 0 || pub.Y.Cmp(gy) != 0 {
		t.Fatalf("parsed point mismatch: X=%v Y=%v", pub.X, pub.Y)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("parsed curve = %v, want P-256", pub.Curve)
	}
}

func TestParseECCPublicBlobRejectsBadMagic(t *testing.T) {
	blob := buildPublicBlob(elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	binary.LittleEndian.PutUint32(blob[0:4], 0xDEADBEEF)
	if _, err := parseECCPublicBlob(blob); err == nil {
		t.Fatal("parseECCPublicBlob accepted bad magic")
	}
}

func TestParseECCPublicBlobRejectsWrongKeySize(t *testing.T) {
	blob := buildPublicBlob(elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	binary.LittleEndian.PutUint32(blob[4:8], 48)
	if _, err := parseECCPublicBlob(blob); err == nil {
		t.Fatal("parseECCPublicBlob accepted wrong cbKey")
	}
}

func TestParseECCPublicBlobRejectsTruncated(t *testing.T) {
	blob := buildPublicBlob(elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	if _, err := parseECCPublicBlob(blob[:len(blob)-1]); err == nil {
		t.Fatal("parseECCPublicBlob accepted truncated blob")
	}
}

func TestParseECCPublicBlobRejectsOffCurve(t *testing.T) {
	blob := buildPublicBlob(big.NewInt(1), big.NewInt(1))
	if _, err := parseECCPublicBlob(blob); err == nil {
		t.Fatal("parseECCPublicBlob accepted a point not on P-256")
	}
}

func p1363(r, s *big.Int) []byte {
	out := make([]byte, 2*ecdsaP256CoordinateSize)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[ecdsaP256CoordinateSize-len(rb):ecdsaP256CoordinateSize], rb)
	copy(out[2*ecdsaP256CoordinateSize-len(sb):2*ecdsaP256CoordinateSize], sb)
	return out
}

func TestP1363ToASN1KnownVector(t *testing.T) {
	sig := p1363(big.NewInt(1), big.NewInt(2))
	got, err := p1363ToASN1(sig)
	if err != nil {
		t.Fatalf("p1363ToASN1: %v", err)
	}
	want := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	if string(got) != string(want) {
		t.Fatalf("p1363ToASN1 = % X, want % X", got, want)
	}
}

func TestP1363ToASN1AddsSignPadding(t *testing.T) {
	sig := p1363(big.NewInt(0xAB), big.NewInt(0xCD))
	got, err := p1363ToASN1(sig)
	if err != nil {
		t.Fatalf("p1363ToASN1: %v", err)
	}
	want := []byte{0x30, 0x08, 0x02, 0x02, 0x00, 0xAB, 0x02, 0x02, 0x00, 0xCD}
	if string(got) != string(want) {
		t.Fatalf("p1363ToASN1 = % X, want % X", got, want)
	}
}

func TestP1363ToASN1RejectsWrongLength(t *testing.T) {
	if _, err := p1363ToASN1(make([]byte, 63)); err == nil {
		t.Fatal("p1363ToASN1 accepted 63-byte signature")
	}
}

func TestP1363ToASN1RejectsZeroComponents(t *testing.T) {
	if _, err := p1363ToASN1(make([]byte, 64)); err == nil {
		t.Fatal("p1363ToASN1 accepted all-zero signature")
	}
}

func TestP1363ToASN1VerifiesAgainstECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("keppin-oss-cng-signature"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	asn1, err := p1363ToASN1(p1363(r, s))
	if err != nil {
		t.Fatalf("p1363ToASN1: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], asn1) {
		t.Fatal("P1363->ASN.1 signature failed ECDSA verification")
	}
}

func TestClosedSignerCannotSign(t *testing.T) {
	s := &cngSigner{key: 0}
	if _, err := s.Sign(nil, []byte("digest"), nil); err == nil {
		t.Fatal("Sign on a closed signer must fail")
	}
}

func TestSignerPublic(t *testing.T) {
	want := &ecdsa.PublicKey{Curve: elliptic.P256()}
	s := &cngSigner{publicKey: want}
	if s.Public() != want {
		t.Fatal("Public() did not return the stored public key")
	}
}

func TestEmptyDigestRejected(t *testing.T) {
	s := &cngSigner{key: 1}
	if _, err := s.Sign(nil, nil, nil); err == nil {
		t.Fatal("Sign with empty digest must fail")
	}
}
