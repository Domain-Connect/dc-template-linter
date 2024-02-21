package internal

// A CheckSeverity represent status of the template check.
type CheckSeverity uint8

const (
	CheckOK    CheckSeverity = 0
	CheckInfo  CheckSeverity = 1 << 0
	CheckWarn  CheckSeverity = 1 << 1
	CheckError CheckSeverity = 1 << 2
	CheckFatal CheckSeverity = 1 << 3
)
