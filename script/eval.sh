#! /bin/bash -x
# usage
#  - script/eval.sh 50006 127.0.0.1 32 1.0 10
port=$1
address=$2
cate_max=$3
epsilon=$4
times=$5

g=0
for width in 100 1000; do
	for mech in krr oue olh; do
		for cate_num in $(seq 2 $cate_max); do
			for i in $(seq 1 $times) ; do
				if [ $cate_num -le 3 ] ; then
					g=2
				else
					g=$(($cate_num / 2))
				fi
				python server.py --mech $mech --cate_num $cate_num --width $width --epsilon $epsilon --port $port --address $address --g $g &
				sleep 1
				python client.py --mech $mech --cate_num $cate_num --width $width --epsilon $epsilon --port $port --address $address --sensitive_value 1 --g $g
			done
		done
	done
done
