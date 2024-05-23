// Package exitvals are used to communicate what level of issues the
// libdctlint/ was able to detect.  The error value should be checked in
// downstream code.
package exitvals

// A CheckSeverity represent status of the template check.
type CheckSeverity uint8

const (
	CheckOK    CheckSeverity = 0
	CheckDebug CheckSeverity = 1 << 0
	CheckInfo  CheckSeverity = 1 << 1
	CheckWarn  CheckSeverity = 1 << 2
	CheckError CheckSeverity = 1 << 3
	CheckFatal CheckSeverity = 1 << 4
)
