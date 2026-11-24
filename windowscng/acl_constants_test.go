package windowscng

// Test data for the descriptor classifier: principals and masks that no
// policy DACL grants and that the classifier must reject.
const (
	genericWrite = 0x40000000 // GENERIC_WRITE

	sidEveryone     = "S-1-1-0"
	sidAuthUsers    = "S-1-5-11"
	sidBuiltinUsers = "S-1-5-32-545"
	sidInteractive  = "S-1-5-4"
	sidService      = "S-1-5-6"
	sidAnonymous    = "S-1-5-7"
)
