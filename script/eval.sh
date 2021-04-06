#! /bin/bash -x
# usage
#  - script/eval.sh 50006 127.0.0.1 100 krr 10 1.0 10
port=$1
address=$2
width=$3
mech=$4
cate_num=$5
epsilon=$6
times=$7
g=$8

for i in $(seq 1 $times) ; do
    echo $i
    python server.py --mech $mech --cate_num $cate_num --width $width --epsilon $epsilon --port $port --address $address --g $g &
    sleep 0.1
    python client.py --mech $mech --cate_num $cate_num --width $width --epsilon $epsilon --port $port --address $address --sensitive_value 1 --g $g
done
