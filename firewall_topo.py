from mininet.topo import Topo

class firewall_topo( Topo ):
    def __init__( self ):
        Topo.__init__( self )

        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')

        self.addLink(switch1, host1)
        self.addLink(switch2,host2)
        self.addLink(switch3,host3)
        self.addLink(switch4,host4)
        self.addLink(switch5,host5)
        self.addLink(switch1,switch2)
        self.addLink(switch1,switch3)
        self.addLink(switch1,switch4)
        self.addLink(switch1,switch5)
        self.addLink(switch2,switch3)
        self.addLink(switch2,switch5)
        self.addLink(switch3,switch4)
        self.addLink(switch4,switch5)

topos = { 'firewall_topo': ( lambda: firewall_topo() ) }