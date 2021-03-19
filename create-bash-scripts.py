import sys

server = int(sys.argv[1])
tun_ip_path = sys.argv[2]
out_dir = sys.argv[3]

with open(tun_ip_path, "r") as infile:
    for line in infile:
        if server:
            tun_interface, ip_addr, _ = line.strip().split(":")
            with open("{}/{}_server.sh".format(out_dir, tun_interface), "w") as outfile:
                outfile.write("#!/bin/sh\n\n# Assigning an IP address and mask to '{}' interface\nifconfig {} mtu 1472 up {} netmask 255.255.255.0\n\n# Preventing the kernel to reply to any ICMP pings\necho 1 | dd of=/proc/sys/net/ipv4/icmp_echo_ignore_all\n\n# Enabling IP forwarding\necho 1 | dd of=/proc/sys/net/ipv4/ip_forward\n\n# Adding an iptables rule to masquerade for 10.0.0.0/8\niptables -t nat -A POSTROUTING -s 10.0.0.0/8 -j MASQUERADE\n".format(tun_interface, tun_interface, ip_addr))
