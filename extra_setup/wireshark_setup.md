# Wireshark QCA packets capture
On the EVSE run the installation:

```
sudo apt update
sudo apt install tcpdump -y
sudo apt install netcat-traditional -y
```

On chosen `COMPUTER`, which must have wireshark and netcat installed, run the command:

```
nc -l -p 15200 | wireshark -k -i -
```

Or using dumpcap
```
nc -l -p 15200 | dumpcap -i - -w capture.pcap
```

And then run command on the EVSE:

```
sudo tcpdump -i eth1 -s 0 -U -w - | nc ISO_OPERATOR_IP 15200
```