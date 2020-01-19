#!/usr/bin/python

'This is test topology for SSP project'

import sys

from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.net import Mininet
from time import sleep

def topology():
    'Create a network and controller'
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    info("*** Creating nodes\n")
     
    h1 = net.addHost('h1', ip='10.0.0.1/24', position='10,10,0')
    h2 = net.addHost('h2', ip='10.0.0.2/24', position='20,10,0')
    
    sw1 = net.addSwitch('sw1', protocols="OpenFlow13", position='12,10,0')
    sw2 = net.addSwitch('sw2', protocols="OpenFlow13", position='15,20,0')
    sw3 = net.addSwitch('sw3', protocols="OpenFlow13", position='18,10,0')
    sw4 = net.addSwitch('sw4', protocols="OpenFlow13", position='14,10,0')
    sw5 = net.addSwitch('sw5', protocols="OpenFlow13", position='16,10,0')
    sw6 = net.addSwitch('sw6', protocols="OpenFlow13", position='14,0,0')
    sw7 = net.addSwitch('sw7', protocols="OpenFlow13", position='16,0,0')

    
    info("*** Adding Link\n")
    net.addLink(h1, sw1)
    net.addLink(sw1, sw2)
    net.addLink(sw1, sw4)
    net.addLink(sw1, sw6)
    net.addLink(sw2, sw3)
    net.addLink(sw4, sw5)
    net.addLink(sw5, sw3)
    net.addLink(sw6, sw7)
    net.addLink(sw7, sw3)
    net.addLink(sw3, h2)


    info("*** Starting network\n")
    net.build()
    c0.start()
    sw1.start([c0])
    sw2.start([c0])
    sw3.start([c0])
    sw4.start([c0])
    sw5.start([c0])
    sw6.start([c0])
    sw7.start([c0])
    

    net.pingFull()
    
    info("*** Running CLI\n")
    CLI( net )

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
