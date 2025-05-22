To install requirements on EVSE (here) run:

```
./wireshark_setup.sh
```

On chosen `COMPUTER`, which must have wireshark and netcat installed, run the command:

```
nc -l -p 15200 | wireshark -k -i -
```

Or using dumpcap:

```
nc -l -p 15200 | dumpcap -i - -w capture.pcap
```

And then run command on the EVSE:

```bash
./wireshark_tcp_dump.sh
```