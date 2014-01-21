# -*- encoding: utf-8 -*-
#
# :authors: Arturo Filastò
# :licence: see LICENSE

from twisted.python import usage
from twisted.internet import defer, reactor

from ooni.templates import scapyt

from scapy.all import *

from ooni.utils import log
from ooni.utils.txscapy import ScapyTraceroute
from ooni.settings import config

class UsageOptions(usage.Options):
    optParameters = [
                    ['backend', 'b', None, 'Test backend to use'],
                    ['timeout', 't', 5, 'The timeout for the traceroute test'],
                    ['maxttl', 'm', 30, 'The maximum value of ttl to set on packets'],
                    ['srcport', 'p', None, 'Set the source port to a specific value (only applies to TCP and UDP)']
                    ]

class TracerouteTest(scapyt.BaseScapyTest):
    name = "Multi Protocol Traceroute Test"
    description = "Performs a UDP, TCP, ICMP traceroute with destination port number set to 0, 22, 23, 53, 80, 123, 443, 8080 and 65535"
    requiredTestHelpers = {'backend': 'traceroute'}
    usageOptions = UsageOptions
    dst_ports = [0, 22, 23, 53, 80, 123, 443, 8080, 65535]
    timeout = 5

    def setUp(self):
        self.st = ScapyTraceroute()
        config.scapyFactory.registerProtocol(self.st)
        self.done = defer.Deferred()

    def test_icmp_traceroute(self):
        self.st.ICMPTraceroute(self.localOptions['backend'])
        d = defer.Deferred()
        reactor.callLater(self.timeout, d.callback, self.st)
        return d

    #def test_tcp_traceroute(self):
    #    self.st.TCPTraceroute(self.localOptions['backend'])
    #    d = defer.Deferred()
    #    reactor.callLater(self.timeout, d.callback, self.st)
    #    return d

    #def test_udp_traceroute(self):
    #    self.st.UDPTraceroute(self.localOptions['backend'])
    #    d = defer.Deferred()
    #    reactor.callLater(self.timeout, d.callback, self.st)
    #    return d

    def postProcessor(self, measurements):
        # should be called after all deferreds have calledback
        self.st.stopListening()
        # do something with all the packets
        if measurements[0][1].result == self.st:
            for packet in self.st.received_packets:
                ll = packet.getlayer(1)
                if isinstance(ll, ICMP):
                    self.matchICMP(packet)
                elif isinstance(ll, TCP):
                    self.matchTCP(packet)
                elif isinstance(ll, UDP):
                    self.matchUDP(packet)
            import pdb;pdb.set_trace()

    def matchICMP(self, packet):
        if packet.getlayer(1).type == 11:
            if isinstance(packet.getlayer(2), IPerror):
                iperr = packet.getlayer(2)
                if isinstance(packet.getlayer(3), ICMPerror):
                    packet.getlayer(2).id
                    icmp = filter(lambda x: isinstance(x.getlayer(1),ICMP), self.st.sent_packets)
                    m = filter(lambda x: x.getlayer(1).id == packet.getlayer(2).id, icmp)
                elif isinstance(packet.getlayer(3), TCPerror):
                    tcp = filter(lambda x: isinstance(x.getlayer(1),TCP), self.st.sent_packets)
                    m = filter(lambda x: x.getlayer(1).id == packet.getlayer(2).id, tcp)
                elif isinstance(packet.getlayer(3), UDPerror):
                    udp = filter(lambda x: isinstance(x.getlayer(1),UDP), self.st.sent_packets)
                    m = filter(lambda x: x.getlayer(1).id == packet.getlayer(2).id, udp)

                
        import pdb;pdb.set_trace()

    def matchTCP(self, packet):
        import pdb;pdb.set_trace()

    def matchUDP(self, packet):
        import pdb;pdb.set_trace()
