package vldmpb

//go:generate protoc -I=. -I=$GOPATH/src/ --go_out=plugins=grpc:. vldm.proto
