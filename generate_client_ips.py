import sys

client_count = int(sys.argv[1])
gateways_interfaces_filepath = sys.argv[2]

gw_int = []
with open(gateways_interfaces_filepath, "r") as infile:
	for line in infile:
		gw_int.append(tuple(line.strip().split(":")))

with open("tun_ip_client.txt", "w") as outfile:
	for i, gw_int_tuple in zip(range(client_count), gw_int):
		outfile.write("tun{}:10.0.1.{}:{}:{}:{}:iotlab{}".format(i, (i+1)*2, gw_int_tuple[0], gw_int_tuple[1], (i+1)*2-1, i+1))