#!/bin/bash -ex

go fmt ./...
go vet ./...
go build
go mod tidy
go work sync
