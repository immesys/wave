# Embedded geth

So it turns out embedding geth is not straightforward. The only technique that
I have found that makes it marginally easier is to vendor the entire go-ethereum
code base (and all their vendored packages) so that the types match, and then
copy the cmd/geth package source to a new package, go through and remove access
to internal packages (i.e we needed to bring the debug package out into a debug.go
file). Then main can be rewritten to take args as a parameter rather than from
os.Args
