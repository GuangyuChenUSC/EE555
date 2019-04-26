Guangyu Chen guangyuc@usc.edu
Lu Xu lxu360@usc.edu

part2_topo.py runs for the topology
part2_router.py runs as the controller

copy part_topo.py to ~/
copy part2_router.py to ~/pox/pox/misc/


open two SSH terminal for Mininet, in the first terminal, run
$sudo killall controller
$sudo mn -c
$ sudo mn --custom part2_topo.py --topo part2_topo --mac --controller=remote,ip=127.0.0.1,port=6633
in the second terminal, run
$ sudo ./pox.py log.level --DEBUG misc.part2_router misc.full_payload

in the first termianl, run
mininet> pingall
mininet> iperf
mininet> xterm h3 h4 h5
in h4, run
#tcpdump -XX -n -i h4-eth1
in h5, run
#tcpdump -XX -n -i h5-eth1
in h3, run
ping -c1 10.0.2.2

for part_2, we use the following reference
https://github.com/hechengu/EE555
https://github.com/zhan849/ee555/tree/master/part2