```
sudo apt install default-jre -y
```

## add to .env

```
##############################################SLAC and ISO15118##############################################
```
on NETWORK_INTERFACE make sure which interface (eth0 or eth1) the qca connected to (haven't made it a fixed 1 yet)
```
################################## fix ipv6
sudo nano /etc/network/interfaces

# interfaces(5) file used by ifup(8) and ifdown(8)

# Please note that this file is written to be used with dhcpcd
# For static IP, consult /etc/dhcpcd.conf and 'man dhcpcd.conf'

# Include files from /etc/network/interfaces.d: 
source-directory /etc/network/interfaces.d

auto eth1
iface eth1 inet6 static
address fe80::1e8:332e:50:2a22
netmask 64

Esta porcaria fica com 2 endereços ipv6, vou ignorar para já, nao consigo resolver

#################################################################################3

git submodule add https://github.com/EcoG-io/iso15118.git

```
sudo apt install pipx
pipx install poetry
cd 
poetry -C charger_ocpp/modules/pyslac install
poetry -C charger_ocpp/modules/iso15118 install
poetry -C charger_ocpp/modules/ocpp install
venv/bin/python -m pip install websockets==14.1
```
<!-- echo "Installing iso15118 python dependencies using poetry -> pyproject.toml"
poetry update--lock
poetry install

fazer igual para pyslac iso15118 e ocpp -->