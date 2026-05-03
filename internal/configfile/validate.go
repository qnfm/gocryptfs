package configfile

import (
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
)

// Validate that the combination of settings makes sense and is supported
func (cf *ConfFile) Validate() error {
	if cf.Version != contentenc.CurrentVersion {
		return fmt.Errorf("unsupported on-disk format %d", cf.Version)
	}
	// scrypt params ok?
	if err := cf.ScryptObject.validateParams(); err != nil {
		return err
	}
	// All feature flags that are in the config file are known?
	for _, flag := range cf.FeatureFlags {
		if !isFeatureFlagKnown(flag) {
			return fmt.Errorf("unknown feature flag %q", flag)
		}
	}
	// File content encryption
	{
		xchacha := cf.IsFeatureFlagSet(FlagXChaCha20Poly1305)
		aessiv := cf.IsFeatureFlagSet(FlagAESSIV)
		aesgem := cf.IsFeatureFlagSet(FlagAESGEM)
		gcmiv128 := cf.IsFeatureFlagSet(FlagGCMIV128)
		hkdf := cf.IsFeatureFlagSet(FlagHKDF)

		// Content encryption modes are mutually exclusive.
		if boolToInt(xchacha)+boolToInt(aessiv)+boolToInt(aesgem) > 1 {
			return fmt.Errorf("can't combine XChaCha20Poly1305, AESSIV, and AESGEM feature flags")
		}

		if aessiv {
			if !gcmiv128 {
				return fmt.Errorf("AESSIV requires GCMIV128 feature flag")
			}
		}

		if xchacha {
			if gcmiv128 {
				return fmt.Errorf("XChaCha20Poly1305 conflicts with GCMIV128 feature flag")
			}
			if !hkdf {
				return fmt.Errorf("XChaCha20Poly1305 requires HKDF feature flag")
			}
		}

		if aesgem {
			if gcmiv128 {
				return fmt.Errorf("AESGEM conflicts with GCMIV128 feature flag")
			}
			if !hkdf {
				return fmt.Errorf("AESGEM requires HKDF feature flag")
			}
		}

		// The absence of other content encryption flags means AES-GCM.
		if !xchacha && !aessiv && !aesgem {
			if !gcmiv128 {
				return fmt.Errorf("AES-GCM requires GCMIV128 feature flag")
			}
		}
	}
	// Filename encryption
	{
		if cf.IsFeatureFlagSet(FlagPlaintextNames) {
			if cf.IsFeatureFlagSet(FlagEMENames) {
				return fmt.Errorf("PlaintextNames conflicts with EMENames feature flag")
			}
			if cf.IsFeatureFlagSet(FlagDirIV) {
				return fmt.Errorf("PlaintextNames conflicts with DirIV feature flag")
			}
			if cf.IsFeatureFlagSet(FlagLongNames) {
				return fmt.Errorf("PlaintextNames conflicts with LongNames feature flag")
			}
			if cf.IsFeatureFlagSet(FlagRaw64) {
				return fmt.Errorf("PlaintextNames conflicts with Raw64 feature flag")
			}
			if cf.IsFeatureFlagSet(FlagLongNameMax) {
				return fmt.Errorf("PlaintextNames conflicts with LongNameMax feature flag")
			}
		}
		if cf.IsFeatureFlagSet(FlagEMENames) {
			// All combinations of DirIV, LongNames, Raw64 allowed
		}
		if cf.LongNameMax != 0 && !cf.IsFeatureFlagSet(FlagLongNameMax) {
			return fmt.Errorf("LongNameMax=%d but the LongNameMax feature flag is NOT set", cf.LongNameMax)
		}
		if cf.LongNameMax == 0 && cf.IsFeatureFlagSet(FlagLongNameMax) {
			return fmt.Errorf("LongNameMax=0 but the LongNameMax feature flag IS set")
		}
	}
	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
