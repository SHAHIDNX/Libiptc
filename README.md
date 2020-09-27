# Libiptc
Manage Linux Iptables Firewall rule programatically using LIBIPTC library

This application demonstrate adding iptables rule programatically using iptc library.
Compilation:
gcc  -o iptc_add_delete_rule iptc_add_delete_rule.c -lip4tc

Run:
To Add a rule:
./iptc_add_delete_rule 1

To Delete a Rule:
./iptc_add_delete_rule 2

Above sample apllication ADD or DELETE UDP port 8000 on INPUT chain with destination IP 10.201.0.238. Request to modify IP accordingly as this sample is just for reference.
