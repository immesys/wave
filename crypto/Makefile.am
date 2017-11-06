# Automake file for keccak

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

## Set the default command-line flags for the C preprocessor to the value
## obtained from pkg-config via PKG_CHECK_MODULES in configure.ac.  These
## flags are passed to the compiler for both C and C++, in addition to the
## language-specific options.
AM_CPPFLAGS = $(EXAMPLE_CFLAGS)

lib_LTLIBRARIES = libed25519prims.la
if FAST
lib_LTLIBRARIES += libed25519primsfast.la
endif
include_HEADERS = ed25519.h ed25519-prims.h ed25519-donna-portable-identify.h
libed25519prims_la_LIBADD = 
libed25519prims_la_LDFLAGS = -version-info ${VERSION} -no-undefined
libed25519prims_la_CFLAGS = @flags@
libed25519prims_la_SOURCES = ed25519-prims.c
libed25519primsfast_la_LIBADD = 
libed25519primsfast_la_LDFLAGS = -version-info ${VERSION} -no-undefined
libed25519primsfast_la_CFLAGS = @fastflags@
libed25519primsfast_la_SOURCES = ed25519-prims.c

install-exec-hook:
	-/sbin/ldconfig $(libdir)
