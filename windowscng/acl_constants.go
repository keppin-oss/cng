package windowscng

// Generic access rights masks — used for structural ACL verification.
const (
	genericAll     = 0x10000000                                               // GENERIC_ALL
	genericRead    = 0x80000000                                               // GENERIC_READ
	genericWrite   = 0x40000000                                               // GENERIC_WRITE
	genericExecute = 0x20000000                                               // GENERIC_EXECUTE
	genericRights  = genericAll | genericRead | genericWrite | genericExecute // extraction mask

	aceTypeAccessAllowed = 0 // ACCESS_ALLOWED_ACE_TYPE
	aclSizeInfoClass     = 2 // AclSizeInformation
)

// Well-known SID strings used as expected / forbidden principals during DACL walk.
const (
	sidSYSTEM         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidLocalService   = "S-1-5-19"
	sidEveryone       = "S-1-1-0"
	sidAuthUsers      = "S-1-5-11"
	sidBuiltinUsers   = "S-1-5-32-545"
	sidInteractive    = "S-1-5-4"
	sidService        = "S-1-5-6"
	sidAnonymous      = "S-1-5-7"
)
