#! /bin/bash -x

# script/onmemory_eval.sh 100 10 1.0 10
width=$1
cate_num=$2
epsilon=$3
g=$4
times=$5

for i in $(seq 1 $times) ; do
    python krr.py --cate_num $cate_num --width $width --epsilon $epsilon --sensitive_value 1
    python oue.py --cate_num $cate_num --width $width --epsilon $epsilon --sensitive_value 1
    python olh.py --cate_num $cate_num --width $width --epsilon $epsilon --g $g --sensitive_value 1
done 