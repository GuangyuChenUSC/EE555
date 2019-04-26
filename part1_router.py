from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
import struct

log = core.getLogger()
class router(object):
    def __init__ (self, fakeways = []):
        log.debug('router registered')
        self.fakeways = fakeways
        self.arpTable = {}
        self.arpWait = {}
        self.routingTable = {}
        self.connections = {}
        self.mac_to_port = {}
        self.ip_to_port = {}

        core.openflow.addListeners(self)


    def _handle_GoingUpEvent(self, event):
        self.listenTo(core.openflow)
        log.debug("Router is up")

    def _handle_ConnectionUp(self,event):
        log.debug("dpid %d: connection is up" % event.dpid)

    def _handle_ConnectionDown(self, event):
        log.debug("dpid %d: connection is down" % event.dpid)
        if event.dpid in self.arpTable:
            del self.arpTable[event.dpid]
        if event.dpid in self.routingTable:
            del self.routingTable[event.dpid]
        if event.dpid in self.connections:
            del self.connections[event.dpid]
        if event.dpid in self.arpWait:
            del self.arpWait[event.dpid]

    def handleArpPacket(self, a, inport, dpid, packet_in):
        log.debug("dpid %d: ARP packet, inport %d, ARP from IP %s to %s" % (dpid, inport, str(a.protosrc), str(a.protodst)))
        if a.prototype == arp.PROTO_TYPE_IP:
            if a.hwtype == arp.HW_TYPE_ETHERNET:
                if a.protosrc != 0:
                    if a.protosrc not in self.arpTable[dpid]:
                        self.arpTable[dpid][a.protosrc] = a.hwsrc
                        log.debug("dpid %d: add ArpTable, IP = %s, mac = %s" % (dpid, str(a.protosrc), str(a.hwsrc)))
                        if a.protosrc in self.arpWait[dpid] and (len(self.arpWait[dpid][a.protosrc]) > 0):
                            self.handleArpWait(a.protosrc,dpid)
                    if a.opcode == arp.REQUEST and a.protodst in self.fakeways:
                        self.handleArpResponse(a, inport, dpid)
        else:
            log.debug("dpid %d: Invalid ARP request")

    def handleArpWait(self, srcIP, dpid):
        log.debug("dpid %d: process ARP wait packet for IP %s" % (dpid, str(srcIP)))
        while len(self.arpWait[dpid][srcIP]) > 0:
            (bid, inport) = self.arpWait[dpid][srcIP][0]
            msg = of.ofp_packet_out(buffer_id = bid, in_port = inport)
            msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][srcIP]))
            msg.actions.append(of.ofp_action_output(port = self.routingTable[dpid][srcIP]))
            self.connections[dpid].send(msg)
            log.debug("dpid %d: send wait ARP packet, destIP: %s, destMAC: %s, output port: %d" % (dpid, str(srcIP), str(self.arpTable[dpid][srcIP]), self.routingTable[dpid][srcIP]))
            del self.arpWait[dpid][srcIP][0]

    def handleArpResponse(self, a, inport, dpid):
        t = arp()   #t is routing, a is ARP
        t.hwtype = a.hwtype
        t.prototype = a.prototype
        t.hwlen = a.hwlen
        t.protolen = a.protolen
        t.opcode = arp.REPLY
        t.hwdst = a.hwsrc
        t.protodst = a.protosrc
        t.protosrc = a.protodst
        t.hwsrc = self.arpTable[dpid][a.protodst]

        e = ethernet(type=ethernet.ARP_TYPE, src=self.arpTable[dpid][a.protodst], dst=a.hwsrc)
        e.set_payload(t)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = inport
        log.debug("dpid %d: inport %d, replying for ARP from %s: mac for IP %s is %s" % (dpid, inport, str(a.protosrc), str(t.protosrc), str(t.hwsrc)))
        self.connections[dpid].send(msg)

    def handleArpRequest(self, packet, inport, dpid):
        t = arp()
        t.hwtype = t.HW_TYPE_ETHERNET
        t.prototype = t.PROTO_TYPE_IP
        t.hwlen = 6
        t.protolen = t.protolen
        t.opcode = t.REQUEST
        t.hwdst = ETHER_BROADCAST
        t.protodst = packet.next.dstip
        t.hwsrc = packet.src
        t.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
        e.set_payload(t)
        log.debug("dpid %d: inport %s, sending ARP request for IP %s from %s" % (dpid, inport,str(t.protodst), str(t.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = inport
        self.connections[dpid].send(msg)

    def handleIcmpRequest(self, dpid, p, srcip, dstip, icmpType):
        pIcmp = icmp()
        pIcmp.type = icmpType
        if icmpType == pkt.TYPE_ECHO_REPLY:
            pIcmp.payload = p.find('icmp').payload
        elif icmpType == pkt.TYPE_DEST_UNREACH:
            oriIp = p.find('ipv4')
            d = oriIp.pack()
            d = d[:oriIp.hl * 4 + 8]
            d = struct.pack("!HH", 0, 0) + d
            pIcmp.payload = d
        pIp = ipv4()
        pIp.protocol = pIp.ICMP_PROTOCOL
        pIp.srcip = dstip
        pIp.dstip = srcip
        e = ethernet()
        e.src = p.dst
        e.dst = p.src
        e.type = e.IP_TYPE
        pIp.payload = pIcmp
        e.payload = pIp

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = self.routingTable[dpid][srcip]
        self.connections[dpid].send(msg)
        log.debug("dpid %d: IP %s ping router at %s" % (dpid, str(srcip), str(dstip)))

    def addNewDpid(self, dpid, connection):
        if dpid not in self.connections:
            self.connections[dpid] = connection
        if dpid not in self.arpTable:
            self.arpTable[dpid]={}
            for i in self.fakeways:
                self.arpTable[dpid][i] = EthAddr("%012x" % (dpid & 0xffffffffffff | 0x0000000000f0,))   #random MAC for swicth
        if dpid not in self.routingTable:
            self.routingTable[dpid]={}
        if dpid not in self.arpWait:
            self.arpWait[dpid]={}

    def validateIP(self, ip):
        ipStr = str(ip)
        temp = ipStr.split('.')
        if temp[0] != '10':
            log.debug("invalid IP %s" % ipStr)
            return False
        if temp[1] != '0':
            log.debug("invalid IP %s" % ipStr)
            return False
        if temp[2] != '1' and temp[2] != '2' and temp[2] != '3':
            log.debug("invalid IP %s" % ipStr)
            return False
        return True


    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = event.connection.dpid
        inport = event.port
        self.addNewDpid(dpid, event.connection)
        if not packet.parsed:
            log.error("Incomplete packet")
            return

        packetIn = event.ofp
        n = packet.next
        if isinstance(n, ipv4):
            log.debug("dpid %d: ipv4 packet inport %d, from %s to %s" % (dpid, inport, packet.next.srcip, packet.next.dstip))
            if n.srcip not in self.routingTable[dpid]:
                self.routingTable[dpid][n.srcip]=inport
                log.debug("dpid %d: adding IPv4 %s to routing table, port number %s" % (dpid, str(n.srcip), inport))
            else:
                log.debug("dpid %d: IP %s already exists, port number %d" % (dpid, str(n.srcip), inport))
            if not self.validateIP(n.dstip):
                log.error("Invalid IP")
                self.handleIcmpRequest(dpid, packet, n.srcip, n.dstip, pkt.TYPE_DEST_UNREACH)
                return
            if n.dstip in self.fakeways:
                if (isinstance(n.next, icmp)) and (n.next.type == pkt.TYPE_ECHO_REQUEST):
                    log.debug("ICMP packet comes to router")
                    self.handleIcmpRequest(dpid, packet, n.srcip, n.dstip, pkt.TYPE_ECHO_REPLY)
            else:
                if n.dstip not in self.routingTable[dpid] or n.dstip not in self.arpTable[dpid]:
                    if n.dstip not in self.arpWait[dpid]:
                        self.arpWait[dpid][n.dstip] = []
                    entry = (packetIn.buffer_id, inport)
                    self.arpWait[dpid][n.dstip].append(entry)
                    log.debug("dpid %d: packet from %s to %s is unkown, adding to ArpWait" % (dpid, str(n.srcip), str(n.dstip)))
                    self.handleArpRequest(packet, inport, dpid)
                else:
                    msg = of.ofp_packet_out(buffer_id=packetIn.buffer_id, in_port=inport)
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port=self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
                    log.debug("dpid %d: packet from %s to %s sent to port %d" % (dpid, str(n.srcip), str(n.dstip), self.routingTable[dpid][n.dstip]))

                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    msg.match.nw_dst = n.dstip
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port=self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
        elif isinstance(n, arp):
            if n.protosrc not in self.routingTable[dpid]:
                self.routingTable[dpid][n.protosrc]=inport
                log.debug("dpid %d: adding IP %s, port %d to routing table" % (dpid, str(n.protosrc), inport))
            else:
                log.debug("dpid %d: IP %s output port %d" % (dpid,str(n.protosrc), inport))
            if not self.validateIP(n.protodst):
                self.handleIcmpRequest(dpid, packet, n.protosrc, n.protodst, pkt.TYPE_DEST_UNREACH)
                return
            self.handleArpPacket(n, inport, dpid, packetIn)

#Valid_IP = ['10.0.1.1', '10.0.1.100', '10.0.2.1', '10.0.2.100', '10.0.3.1', '10.0.3.100']

def launch ():
    gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1']
    fakeways = [IPAddr(x) for x in gateways]
    #log.debug(str(fakeways))
    core.registerNew(router, fakeways)
