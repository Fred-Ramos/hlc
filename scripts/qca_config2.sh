#====================== Detect QCA interface ========================== #
QCA_IFACE=""

for iface in $(ls /sys/class/net/); do
    if [[ "$(readlink -f /sys/class/net/$iface/device/driver 2>/dev/null)" == *"qca"* ]]; then
        QCA_IFACE=$iface
        break
    fi
done

if [ -z "$QCA_IFACE" ]; then
    echo "QCA7000 interface not found. Exiting."
    exit 1
fi

echo "Detected QCA7000 interface: $QCA_IFACE"

#====================== Generate IPv6 address ========================== #
# Prefix part of the address
PREFIX="fe80::494e:4553"

SERIAL=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}') #3rd element is the actual serial number
echo "Serial number of Raspberry: $SERIAL"

HASH=$(echo -n "$SERIAL" | sha256sum) 
echo "Hash of the Serial number: $HASH"

PART1=$(echo $HASH | cut -c 1-4)  # First 4 characters
PART2=$(echo $HASH | cut -c 5-8)  # Last 4 characters
ADDRESS="$PREFIX:$PART1:$PART2"   # Construct the full IPv6 address
echo "Generated IPv6 address: $ADDRESS"

# Step 2: Check if "inet6 static" is already configured for this interface
if grep -q "iface $QCA_IFACE inet6 static" /etc/network/interfaces; then
    echo "IPv6 static configuration already exists for $QCA_IFACE. Skipping."
else
    echo "Appending IPv6 static configuration for $QCA_IFACE to /etc/network/interfaces..."
    sudo tee -a /etc/network/interfaces > /dev/null <<EOL

# Configuration for $QCA_IFACE (QCA7000)
auto $QCA_IFACE
iface $QCA_IFACE inet6 static
    address $ADDRESS
    netmask 64
    accept_ra 0
    autoconf 0
EOL
    echo "Configuration added successfully."
fi
