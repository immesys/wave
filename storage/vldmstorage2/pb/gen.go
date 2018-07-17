package pb

//go:generate protoc -I=. -I=$GOPATH/src/ --go_out=plugins=grpc:. meta.proto
