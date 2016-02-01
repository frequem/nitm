# nitm
Neanderthal in the Middle - A basic MitM command line tool without any special features

#Building
You will need libpcap and libnet:

    apt-get install libpcap0.8 libpcap0.8-dev libnet1 libnet1-dev
To build, run:

    make

#Usage

nitm must be run as root.

    nitm <interface> <ip_target_one> <ip_target_two>
    e.g. nitm eth0 192.168.0.1 192.168.0.7
    
if you dont provide an interface, it will automatically be selected.

    nitm <ip_target_one> <ip_target_two>
    e.g. nitm 192.168.0.1 192.168.0.7

These commands will ARP spoof <code>192.168.0.1</code> and <code>192.168.0.7</code>. All received packets will be piped pack into the network.

#License

This is under the GPLv3 license.
