#!/bin/bash
set -ueo pipefail

cd "$(dirname "$0")"

stat wheezy.img || wget https://storage.googleapis.com/syzkaller/wheezy.img
stat wheezy.img.key || wget https://storage.googleapis.com/syzkaller/wheezy.img.key
chmod 600 wheezy.img.key
