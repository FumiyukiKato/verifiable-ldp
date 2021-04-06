#! /bin/bash -x

# script/onmemory_eval.sh 10
times=$1

for i in {1..$times} ; do
    python krr.py
    python oue.py
    python olh.py
done 