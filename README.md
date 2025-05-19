## Overview

This codebase is designed to be used as a **submodule** within an external EVSE system that complies with the IEC 61851 standard. It extends existing functionality by adding support for the ISO 15118 communication protocol and SLAC (Signal Level Attenuation Characterization) handling via the Pyslac module.


# QCA Setup

Run the following scripts in order with a reboot after each:

```bash
./qca_config.sh
```

```bash
sudo reboot
```

```bash
./qca_config2.sh
```

```bash
sudo reboot
```

# Modules

Run

```bash
poetry -C charger_ocpp/modules/pyslac install
poetry -C charger_ocpp/modules/iso15118 install
```