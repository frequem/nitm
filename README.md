# nitm
Neanderthal in the Middle - A basic MitM command line tool without any special features

#Building

To build, run:

    make

You need libpcap and libnet installed on your machine!

#Usage

nitm must be run as root.

    nitm -i <interface>  -t1 <ip_target_one> -t2 <ip_target_two>
    e.g. nitm -i eth0 -t1 192.168.0.1 -t2 192.168.0.7
    
if you dont provide an interface, it will automatically be selected.

    nitm -t1 <ip_target_one> -t2 <ip_target_two>
    e.g. nitm -t1 192.168.0.1 -t2 192.168.0.7

These commands will ARP spoof <code>192.168.0.1</code> and <code>192.168.0.7</code>. All received packets will be piped back into the network.

#License

This is under the GPLv3 license.
