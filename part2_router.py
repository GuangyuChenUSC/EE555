from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr
import struct
import time

log = core.getLogger()
DEFAULT_GATEWAY = 1
validIP = [IPAddr('10.0.1.1'), IPAddr('10.0.1.2'), IPAddr('10.0.1.3'), IPAddr('10.0.2.1'), IPAddr('10.0.2.2'), IPAddr('10.0.2.3'), IPAddr('10.0.2.4')]
subnet1 = ['10.0.1.1', '10.0.1.2', '10.0.1.3']
subnet2 = ['10.0.2.1', '10.0.2.2', '10.0.2.3', '10.0.2.4']

class router(object):
    def __init__(self):
        log.debug('router registered')
        self.arpTable = {}
        self.arpWait = {}
        self.routingTable = {}
        self.connections = {}
        self.routerIP = {}
        core.openflow.addListeners(self)

    def _handle_GoingUpEvent(self, event):
        self.listenTo(core.openflow)
        log.debug("Router is up")

    def _handle_ConnectionUp(self, event):
        log.debug("dpid %d: connection is up" % event.dpid)
        dpid = event.dpid
        ip = IPAddr('10.0.%d.1' % dpid)
        mac = EthAddr("%012x" % (event.dpid & 0xffffffffffff | 0x0000000000f0,))
        self.routerIP[dpid] = ip
        if dpid not in self.connections:
            self.connections[dpid] = event.connection
        if dpid not in self.arpTable:
            self.arpTable[dpid] = {}
        if dpid not in self.routingTable:
            self.routingTable[dpid] = {}
        if dpid not in self.arpWait:
            self.arpWait[dpid] = {}
        self.arpTable[dpid][ip] = mac
        log.debug("dpid %d: adding mac %s IP %s as router" % (dpid, mac, ip))
        if len(self.routerIP) == 2:
            self.handleArpRequest(ip, IPAddr('10.0.%d.1' %(3-event.dpid)), mac, of.OFPP_FLOOD, dpid)

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
        if event.dpid in self.routerIP:
            del self.routerIP[event.dpid]

    def sendPacket(self, dpid, packetIn, outPort):
        msg = of.ofp_packet_out()
        msg.data = packetIn
        action = of.ofp_action_output(port=outPort)
        msg.actions.append(action)
        self.connections[dpid].send(msg)

    def handleArpPacket(self, a, inport, dpid, packetIn):
        log.debug("dpid %d: ARP packet, inport %d, ARP from IP %s to %s" % (dpid, inport, str(a.protosrc), str(a.protodst)))
        if a.prototype == arp.PROTO_TYPE_IP:
            if a.hwtype == arp.HW_TYPE_ETHERNET:
                if a.protosrc != 0:
                    if a.protosrc not in self.arpTable[dpid]:
                        self.arpTable[dpid][a.protosrc] = a.hwsrc
                        log.debug("dpid %d: add ArpTable, IP  %s, mac %s" % (dpid, str(a.protosrc), str(a.hwsrc)))
                        if a.protosrc in self.arpWait[dpid] and (len(self.arpWait[dpid][a.protosrc]) > 0):
                            self.handleArpWait(a.protosrc,dpid)
                    if a.opcode == arp.REQUEST:
                        if str(a.protodst) == str(self.routerIP[dpid]):
                            self.handleArpResponse(a, inport, dpid)
                        else:
                            self.sendPacket(dpid, packetIn, of.OFPP_FLOOD)
                    elif a.opcode == arp.REPLY and a.protodst != IPAddr('10.0.%d.1' % (dpid)):
                        self.sendPacket(dpid, packetIn, self.routingTable[dpid][a.protodst])
        else:
            log.debug("dpid %d: Unkown ARP request, flooding")
            self.sendPacket(dpid, packetIn, of.OFPP_FLOOD)

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
        t = arp()  # t is routing, a is ARP
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

    def handleArpRequest(self, srcip, dstip, srcmac, inport, dpid):
        t = arp()
        t.hwtype = t.HW_TYPE_ETHERNET
        t.prototype = t.PROTO_TYPE_IP
        t.hwlen = 6
        t.protolen = t.protolen
        t.opcode = t.REQUEST
        t.hwdst = ETHER_BROADCAST
        t.protodst = dstip
        t.hwsrc = srcmac
        t.protosrc = srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=srcmac, dst=ETHER_BROADCAST)
        e.set_payload(t)
        log.debug("dpid %i: inport %s, sending ARP request for IP %s from %s" % (dpid, inport,str(t.protodst), str(t.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        #msg.in_port = inport
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
        if (srcip in subnet1 and self.routerIP[dpid] in subnet1) or (srcip in subnet2 and self.routerIP[dpid] in subnet2):
            e.dst = p.src
        else:
            gatewayIP = IPAddr('10.0.%d.1' % (3-dpid))
            e.dst = self.arpTable[dpid][gatewayIP]
        e.type = e.IP_TYPE
        pIp.payload = pIcmp
        e.payload = pIp

        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.data = e.pack()
        msg.in_port = self.routingTable[dpid][srcip]
        self.connections[dpid].send(msg)
        log.debug("dpid %d: IP %s ping router at %s" % (dpid, str(srcip), str(dstip)))

    def addIP(self, ip, dpid, inport):
        if ip not in self.routingTable[dpid]:
            log.debug("dpid %d: adding IP %s to routing table, port %d" % (dpid, str(ip), inport))
            self.routingTable[dpid][ip] = inport
        else:
            log.debug("dpid %d: IP %s already in routing table, port %d" % (dpid, str(ip), inport))

    def _handle_PacketIn (self, event):
        packet = event.parsed
        dpid = event.connection.dpid
        inport = event.port
        if not packet.parsed:
            log.error("Incomplete packet")
            return
        packetIn = event.ofp
        n = packet.next
        if isinstance(n, ipv4):
            log.debug("dpid %d: ipv4 packet inport %d, from %s to %s" % (dpid, inport, packet.next.srcip, packet.next.dstip))
            self.addIP(n.srcip, dpid, inport)
            if n.dstip not in validIP:
                self.handleIcmpRequest(dpid, packet, n.srcip, n.dstip, pkt.TYPE_DEST_UNREACH)
                return
            if str(n.dstip) == str(self.routerIP[dpid]):
                if isinstance(n.next, icmp):
                    log.debug("DPID %d: ICMP packet comes to router" % dpid)
                    if n.next.type == pkt.TYPE_ECHO_REQUEST:
                        self.handleIcmpRequest(dpid, packet, n.srcip, n.dstip, pkt.TYPE_ECHO_REPLY)
            #different subnet
            elif (n.dstip in subnet1 and self.routerIP[dpid] in subnet2) or (n.dstip in subnet2 and self.routerIP[dpid] in subnet1):
                nextIP = IPAddr('10.0.%d.1' % (3-dpid))
                nextMac = self.arpTable[dpid][nextIP]
                msg = of.ofp_packet_out(buffer_id=packetIn.buffer_id, in_port=inport)
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextMac))
                msg.actions.append(of.ofp_action_output(port=1))
                self.connections[dpid].send(msg)
                log.debug('DPID %d: packet from %s to %s, is in different subnet, send to port %d', dpid, str(n.srcip),str(n.dstip), 1)

                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_dst = n.dstip
                msg.actions.append(of.ofp_action_dl_addr.set_dst(nextMac))
                msg.actions.append(of.ofp_action_output(port=1))
                self.connections[dpid].send(msg)
            #same subnet
            else:
                if n.dstip not in self.routingTable[dpid] or n.dstip not in self.arpTable[dpid]:
                    if n.dstip not in self.arpWait[dpid]:
                        self.arpWait[dpid][n.dstip] = []
                    entry = (packetIn.buffer_id, inport)
                    self.arpWait[dpid][n.dstip].append(entry)
                    log.debug("DPID %d, packet from %s to %s, unknown destination, add to arpWait" % (dpid, str(n.srcip), str(n.dstip)))
                    self.handleArpRequest(n.srcip, n.dstip, packet.src, inport, dpid)
                else:
                    msg = of.ofp_packet_out(buffer_id=packetIn.buffer_id, in_port=inport)
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port=self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
                    log.debug('DPID %d: packet from %s to %s, same subnet, send to port %d', dpid, str(n.srcip),str(n.dstip), self.routingTable[dpid][n.dstip])

                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x800
                    msg.match.nw_dst = n.dstip
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[dpid][n.dstip]))
                    msg.actions.append(of.ofp_action_output(port=self.routingTable[dpid][n.dstip]))
                    self.connections[dpid].send(msg)
        elif isinstance(n, arp):
            self.addIP(n.protosrc, dpid, inport)
            self.handleArpPacket(n, inport, dpid, packetIn)


def launch():
    core.registerNew(router)