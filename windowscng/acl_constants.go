package windowscng

// Generic access rights masks used by the descriptor classifier (sd.go).
const (
	genericAll     = 0x10000000 // GENERIC_ALL
	genericRead    = 0x80000000 // GENERIC_READ
	genericExecute = 0x20000000 // GENERIC_EXECUTE

	aceTypeAccessAllowed = 0 // ACCESS_ALLOWED_ACE_TYPE
)

// Well-known SID strings: the principals of the policy DACLs, also used by the
// privilege check (SYSTEM, Administrators).
const (
	sidSYSTEM         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidLocalService   = "S-1-5-19"
)
