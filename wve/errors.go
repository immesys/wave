package wve

import (
	"context"
	"fmt"
)

// This defines all the errors that BTrDB can throw
type wVE struct {
	code   int
	reason string
	cause  error
}

type WVE interface {
	error
	Code() int
	Reason() string
	Cause() error
}

func (wve *wVE) Code() int {
	return wve.code
}

func (wve *wVE) Reason() string {
	return wve.reason
}

func (wve *wVE) Cause() error {
	return wve.cause
}

func (wve *wVE) WrappedErrors() []error {
	return []error{wve.cause}
}
func (wve *wVE) Error() string {
	if wve.cause == nil {
		return fmt.Sprintf("(%d: %s)", wve.code, wve.reason)
	}
	return fmt.Sprintf("(%d: %s because %s)", wve.code, wve.reason, wve.cause.Error())

}

func MaybeWrap(err error) WVE {
	bt, ok := err.(WVE)
	if ok {
		return bt
	}
	return Err(UnknownError, err.Error())
}

// Error codes:
// 400+ normal user errors
// 500+ abnormal errors that sysadmin should be notified about

func Err(code int, reason string) WVE {
	// if code >= 500 {
	// 	fmt.Fprintf(os.Stderr, "\n\n=== %d code error ===\nreason: %s\n", code, reason)
	// 	debug.PrintStack()
	// 	fmt.Fprintf(os.Stderr, "====\n\n")
	// }
	return &wVE{
		code:   code,
		reason: reason,
		cause:  nil,
	}
}
func ErrF(code int, reasonz string, args ...interface{}) WVE {
	reason := fmt.Sprintf(reasonz, args...)
	// if code >= 500 {
	// 	fmt.Fprintf(os.Stderr, "\n\n=== %d code error ===\nreason: %s\n", code, reason)
	// 	debug.PrintStack()
	// 	fmt.Fprintf(os.Stderr, "====\n\n")
	// }
	return &wVE{
		code:   code,
		reason: reason,
		cause:  nil,
	}
}
func ErrW(code int, reason string, cause error) WVE {
	// if code >= 500 {
	// 	fmt.Fprintf(os.Stderr, "\n\n=== %d code error ===\nreason: %s\nbecause: %s", code, reason, cause.Error())
	// 	debug.PrintStack()
	// 	fmt.Fprintf(os.Stderr, "====\n\n")
	// }
	scause := "<nil>"
	if cause != nil {
		scause = cause.Error()
	}
	return &wVE{
		code:   code,
		reason: fmt.Sprintf("%s (%s)", reason, scause),
		cause:  cause,
	}
}
func CtxE(ctx context.Context) WVE {
	if ctx.Err() == nil {
		return nil
	}
	return &wVE{
		code:   ContextError,
		reason: fmt.Sprintf("%s (%s)", "context error", ctx.Err()),
		cause:  ctx.Err(),
	}
}
func Chan(e WVE) chan WVE {
	rv := make(chan WVE, 1)
	rv <- e //buffered
	return rv
}

//Context errors cascade quite a bit and tend to cause duplicate errors
//in the return channel. Try not to leak goroutiens by]
//blocking on them
func ChkContextError(ctx context.Context, rve chan WVE) bool {
	if ctx.Err() != nil {
		select {
		case rve <- CtxE(ctx):
		default:
		}
		return true
	}
	return false
}
func NoBlockError(e WVE, ch chan WVE) {
	if e != nil {
		select {
		case ch <- e:
		default:
		}
	}
}

const GRPCCancelled = 100

// Things like user timeout
const ContextError = 101

const GRPCUnknown = 200

//A generic error that might be the user's fault
const UnknownError = 201

//An internal error that is most likely a bug
const InternalError = 202
const BodySchemeError = 203
const StorageError = 204
const GRPCInvalidArgument = 300
const MissingParameter = 301
const PassphraseRequired = 302
const KeyringDecryptFailed = 303
const InvalidParameter = 304
const InvalidMultihash = 305
const GRPCNotFound = 500
const GRPCAlreadyExists = 600
const GRPCFailedPrecondition = 900
const UnsupportedHashScheme = 901
const UnsupportedBodyScheme = 902
const UnsupportedKeyScheme = 903
const MalformedDER = 904
const UnexpectedObject = 905
const InvalidSignature = 906
const MalformedObject = 907
const UnsupportedSignatureScheme = 908
const LookupFailure = 909
const UnsupportedLocationScheme = 910
