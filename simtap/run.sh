#!/bin/bash
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo setcap cap_net_admin=eip target/release/simtap
$CARGO_TARGET_DIR/release/simtap &
pid=$
sleep 1
sudo ifconfig utun1 192.168.166.1 192.168.166.2 up
trap "kill $pid" INT TERM
wait $pid