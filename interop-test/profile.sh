#!/bin/bash -ex

go test -run XXX -bench BenchmarkConn -benchtime 30000x -cpuprofile cpu.out
go test -run XXX -bench Benchmark[^C] -benchtime 30000x

go tool pprof interop-test.test cpu.out
