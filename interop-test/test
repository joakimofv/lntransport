#!/bin/bash -ex

go test -fuzz FuzzWithLndSend -fuzztime 5s
go test -run XXX -fuzz FuzzWithLndReceive -fuzztime 5s
