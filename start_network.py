"""
Creates a simple topology using Mininet
"""
import os
import time
import atexit

from mininet.topo import Topo
from mininet.node import TCIntf, RemoteController
from mininet.link import TCLink
from mininet.util import custom
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.log import lg

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import sendp, send

from tabulate import tabulate
import crayons as cr

class SimpleTopology(Topo):

    def build(self):
        """ Creates a Mininet topology

        Effect:
            Creating final topology

        Returns:
            None
        """
        
        # Hosts
        self.h1 = self.addHost('h1', ip="10.0.1.1/24")
        self.h2 = self.addHost('h2', ip="10.0.2.1/24")
        
        # Switches
        self.addSwitch('s1')
        self.addSwitch('s2')
        self.addSwitch('s3')

        # Host <-> Switch Links
        self.addLink('h1', 's1')
        self.addLink('h2', 's2')
        
        # Switch <-> Switch Links
        self.addLink('s1', 's2')

class SimpleCLI(CLI):
    prompt = 'cmpt471> '

    helpStr = (
        'You may also send a command to a node using:\n'
        '  <node> command {args}\n'
        'For example:\n'
        '  cmpt471> h1 ifconfig\n'
        '\n'
        'The interpreter automatically substitutes IP addresses\n'
        'for node names when a node is the first arg, so commands\n'
        'like\n'
        '  cmpt471> h2 ping h3\n'
        'should work.\n'
        '\n'
        'Some character-oriented interactive commands require\n'
        'noecho:\n'
        '  cmpt471> noecho h2 vi foo.py\n'
        'However, starting up an xterm/gterm is generally better:\n'
        '  cmpt471> xterm h2\n\n'
    )

    def __init__(self, mininet):
        atexit.register(lambda: self.do_bye(None))

        CLI.__init__(self, mininet)

    def do_list_hosts(self, _line):
        """List hosts"""

        servers = []
        for host in self.mn.hosts:
            servers.append([cr.normal(host), cr.normal(host.IP())])
        lg.output(tabulate(servers, headers=[cr.normal('Host', bold=True), cr.normal('IP', bold=True)],
                           tablefmt='grid'))
        lg.output('\n')

    def do_list_switches(self, _line):
        """List switches"""

        switches = []
        for switch in self.mn.switches:
            connectedStr = cr.red('NO')
            if switch.connected():
                connectedStr = cr.green('YES')
            switches.append([cr.normal(switch), cr.normal(switch.dpid), connectedStr])

        lg.output(tabulate(switches, headers=[cr.normal('Switch', bold=True), cr.normal('Dpid', bold=True), cr.normal('Connected?', bold=True)],
                           tablefmt='grid'))
        lg.output('\n')

    def do_clear_rules(self, _line):
        h1 = self.mn.hosts[0]
        h2 = self.mn.hosts[1]
        h1.cmd('python3 send_command.py %s %s %s %s 252 h1-eth0' % (h1.MAC(), h2.MAC(), h1.IP(), h2.IP()))

    def do_set_default(self, _line):
        h1 = self.mn.hosts[0]
        h2 = self.mn.hosts[1]
        h1.cmd('python3 send_command.py %s %s %s %s 253 h1-eth0' % (h1.MAC(), h2.MAC(), h1.IP(), h2.IP()))
        
    def do_set_alternative(self, _line):
        h1 = self.mn.hosts[0]
        h2 = self.mn.hosts[1]
        h1.cmd('python3 send_command.py %s %s %s %s 254 h1-eth0' % (h1.MAC(), h2.MAC(), h1.IP(), h2.IP()))

    def do_bye(self, _line):
        lg.output('Bye :)')
        lg.output('\n')

def SimpleNet(**kwargs):
    """ Creates the Simple topology and Mininet network.

    Args:
        **kwargs: additional kwargs to the Mininet object

    Returns:
        The Mininet network with the corresponding topology.
        None if the topology file is invalid
    """

    topo = SimpleTopology()
    network = Mininet(topo, controller=RemoteController, waitConnected=False, **kwargs)
    link23 = network.addLink('s2', 's3', cls=TCLink)
    link13 = network.addLink('s1', 's3', cls=TCLink)

    link23.intf1.config(delay='15ms')
    link23.intf2.config(delay='15ms')

    link13.intf1.config(delay='15ms')
    link13.intf2.config(delay='15ms')
    return network

if __name__ == '__main__':
    network = SimpleNet()
    if not network:
        print('The Mininet network was not created!')
        exit(1)

    h1 = network.hosts[0]
    h2 = network.hosts[1]

    # Set up ARP rules; no need for our switches to forward ARP pkts
    h1.cmd('arp -s %s -i h1-eth0 %s' % (h2.IP(), h2.MAC()))
    h2.cmd('arp -s %s -i h2-eth0 %s' % (h1.IP(), h1.MAC()))

    # Add default gateways for h1 and h2, as they are in separate subnets
    h1.cmd("ip route add default via %s" % h1.IP())
    h2.cmd("ip route add default via %s" % h2.IP())
    
    # Diable IPv6 for hosts and switches 
    for h in network.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    for sw in network.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    network.start()
    SimpleCLI(mininet=network)
    network.stop()
