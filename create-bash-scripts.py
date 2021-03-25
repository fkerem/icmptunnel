import sys

server = int(sys.argv[1])
tun_ip_path = sys.argv[2]
out_dir = sys.argv[3]

if server == 0:
    server_addr = sys.argv[4]
else:
    server_addr = None

with open(tun_ip_path, "r") as infile:
    for ind, line in enumerate(infile):
        if server:
            tun_interface, ip_addr, _ = line.strip().split(":")
            with open("{}/{}_server.sh".format(out_dir, tun_interface), "w") as outfile:
                outfile.write("#!/bin/sh\n\n# Assigning an IP address and mask to '{}' interface\nifconfig {} mtu 1472 up {} netmask 255.255.255.0\n\n# Preventing the kernel to reply to any ICMP pings\necho 1 | dd of=/proc/sys/net/ipv4/icmp_echo_ignore_all\n\n# Enabling IP forwarding\necho 1 | dd of=/proc/sys/net/ipv4/ip_forward\n\n# Adding an iptables rule to masquerade for 10.0.0.0/8\niptables -t nat -A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE\n".format(tun_interface, tun_interface, ip_addr))
        else:
            tun_interface, ip_addr, gateway, interface, server_tun_addr, _ = line.strip().split(":")
            with open("{}/client{}.sh".format(out_dir, ind+1), "w") as outfile:
                outfile.write("#!/bin/sh\n\n# Assigining an IP address and mask to '{}' interface\nifconfig {} mtu 1472 up {} netmask 255.255.255.0\n\n# Modifying IP routing tables\nroute del default\n# 'server' is the IP address of the proxy server\n# 'gateway' and 'interface' can be obtained by usint the command: 'route -n'\nroute add -host {} gw {} dev {}\nroute add default gw {} {}\n".format(tun_interface, tun_interface, ip_addr, server_addr, gateway, interface, server_tun_addr, tun_interface))