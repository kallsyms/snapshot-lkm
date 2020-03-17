#!/bin/bash
set -ueo pipefail

pushd snapshot
make
popd

pushd test
make
popd

scp -i wheezy.img.key -P 10022 snapshot/snapshotko.ko root@localhost:
scp -i wheezy.img.key -P 10022 test/test root@localhost:
scp -i wheezy.img.key -P 10022 -r perf-fuzz/afl root@localhost:
scp -i wheezy.img.key -P 10022 -r perf-fuzz/afl-test root@localhost:
