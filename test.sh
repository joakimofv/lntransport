#!/bin/bash -ex

go test -fuzz . -fuzztime 5s
cd interop-test
./test.sh
cd -
