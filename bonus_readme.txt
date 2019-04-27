Guangyu Chen guangyuc@usc.edu
Lu Xu lxu360@usc.edu

part3_topo.py is the topology of the first part
firewall_topo.py is the topology of the second part
firewall.py runs as the controller of firewall

For firewall part, open two SSH terminal for Mininet, in the first terminal, run
$sudo killall controller
$sudo mn -c
$ sudo mn --custom firewall_topo.py --topo firewall_topo --mac --controller=remote,ip=127.0.0.1,port=6633
in the second terminal, run
$ sudo ./pox.py forwarding.l2_learning openflow.discovery openflow.spanning_tree --no-flood --hold-down pox.misc.firewall

in the first termianl, run
mininet> pingall
mininet> xterm h2 h3
in h3, run
#iperf -s
in h2, run
#iperf -c 10.0.0.2

for firewall part, we use the following reference
https://github.com/esha2008/SDN_firewall