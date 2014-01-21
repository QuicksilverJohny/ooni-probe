# -*- encoding: utf-8 -*-
#
# :authors: Arturo Filastò
# :licence: see LICENSE

from twisted.python import usage
from twisted.internet import defer

from ooni.templates import scapyt

from scapy.all import *

from ooni.utils import log
from ooni.utils.txscapy import ScapyTraceroute

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
        self.scapyFactory.registerProtocol(self.st)
        self.done = defer.Deferred()

    def test_icmp_traceroute(self):
        self.st.ICMPTraceroute(self.localOptions['backend'])
        d = defer.Deferred()
        reactor.callLater(self.timeout, d.callback)
        return d

    def test_tcp_traceroute(self):
        self.st.TCPTraceroute(self.localOptions['backend'])
        d = defer.Deferred()
        reactor.callLater(self.timeout, d.callback)
        return d

    def test_udp_traceroute(self):
        self.st.UDPTraceroute(self.localOptions['backend'])
        d = defer.Deferred()
        reactor.callLater(self.timeout, d.callback)
        return d

    def postProcessor(self, measurements):
        # should be called after all deferreds have calledback
        self.st.stopListening()
        # do something with all the packets
        import pdb;pdb.set_trace()
