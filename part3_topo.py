from mininet.topo import Topo

class part3_topo(Topo):
    def __init__(self):
        Topo.__init__(self)

        host1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        host2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        host3 = self.addHost('h3', ip='10.0.1.4/24', defaultRoute='via 10.0.1.1')
        host4 = self.addHost('h4', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        host5 = self.addHost('h5', ip='10.0.2.3/24', defaultRoute='via 10.0.2.1')
        host6 = self.addHost('h6', ip='10.0.2.4/24', defaultRoute='via 10.0.2.1')
        host7 = self.addHost('h7', ip='10.0.3.2/24', defaultRoute='via 10.0.3.1')
        host8 = self.addHost('h8', ip='10.0.3.3/24', defaultRoute='via 10.0.3.1')
        host9 = self.addHost('h9', ip='10.0.3.4/24', defaultRoute='via 10.0.3.1')

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')

        # Add links
        self.addLink('s1', 's2', port1=1, port2=1)
        self.addLink('s2', 's3', port1=2, port2=1)
        self.addLink('h1', 's1', port1=1, port2=2)
        self.addLink('h2', 's1', port1=1, port2=3)
        self.addLink('h3', 's1', port1=1, port2=4)
        self.addLink('h4', 's2', port1=1, port2=3)
        self.addLink('h5', 's2', port1=1, port2=4)
        self.addLink('h6', 's2', port1=1, port2=5)
        self.addLink('h7', 's3', port1=1, port2=2)
        self.addLink('h8', 's3', port1=1, port2=3)
        self.addLink('h9', 's3', port1=1, port2=4)


topos = {'part3_topo': (lambda: part3_topo())}