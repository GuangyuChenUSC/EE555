Guangyu Chen guangyuc@usc.edu
Lu Xu lxu360@usc.edu

of_tutoral.py runs as a learning switch
part1_topo.py runs for the topology
part1_router.py runs as the controller

copy of_tutorial.py and part1_router.py to ~/pox/pox/misc/
copy part1_topo.py to ~/

open two SSH terminal for Mininet, in the first terminal, run
$sudo killall controller
$sudo mn -c
$sudo mn --topo single,3 --mac --switch ovsk --controller remote,ip=127.0.0.1,port=6633
in the second terminal, run
$cd pox
$./pox.py log.level --DEBUG misc.of_tutorial

if you need to test the learing switch, in the first termianl, run
mininet> xterm h1 h2 h3
in h2, run
#tcpdump -XX -n -i h2-eth0
in h3, run
#tcpdump -XX -n -i h3-eth0
in h1, to ping h2, run 
#ping -c1 10.0.0.2

before test the router part, run
mininet> exit
$sudo mn -c
if you need to test the router, in the first terminal, run
$ sudo mn --custom part1_topo.py --topo part1_topo --mac --controller=remote,ip=127.0.0.1,port=6633
in the second terminal run
$ sudo ./pox.py log.level --DEBUG misc.part1_router misc.full_payload

in the first terminal, run 
mininet> pingall
mininet> iperf
mininet> xterm h1 h2 h3
in h2, run
#tcpdump -XX -n -i h2-eth0
in h3, run
#tcpdump -XX -n -i h3-eth0
in h1, run
#ping -c1 10.0.99.100

for part_1, we use the following reference
https://github.com/hechengu/EE555
https://github.com/zhan849/ee555/tree/master/part1