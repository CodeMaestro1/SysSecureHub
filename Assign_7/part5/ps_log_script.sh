while true; do
	ps -o pid,%cpu,%mem,cmd -C $1 >> ps_log.txt
	sleep 0.001
done
