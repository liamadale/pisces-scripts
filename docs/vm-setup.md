# Ubuntu VM Setup

This guide covers creating an Ubuntu VM for running the PISCES toolkit and connecting
it to the cyber range network via OpenVPN.

---

## Recommended VM specs

| | |
|---|---|
| **OS** | Ubuntu 24.04 LTS or 26.04 LTS (desktop or server) |
| **CPUs** | 2–4 vCPUs |
| **RAM** | 4 GB minimum, 8 GB recommended |
| **Disk** | 40 GB minimum |
| **Network adapter** | NAT or bridged — either works for initial setup |

Any hypervisor works (VirtualBox, VMware, Hyper-V, GNOME Boxes, etc.). Use whichever
you're already comfortable with.

---

## Required packages

After Ubuntu is installed and you have a terminal, install the following:

```bash
sudo apt update && sudo apt install -y git curl openvpn
```

| Package | Purpose |
|---|---|
| `git` | Cloning the pisces-scripts repository |
| `curl` | Installing `uv` (the package manager) |
| `openvpn` | Connecting to the cyber range network |

Python 3 is included with Ubuntu by default — no separate install needed.

---

## Getting your OpenVPN certificate onto the VM

The easiest way to transfer your `.ovpn` certificate from your host machine to the VM
is to serve it temporarily over HTTP.

**On your host machine**, navigate to the folder containing your certificate and run:

```bash
python3 -m http.server 8080
```

**On the VM**, download the certificate — replacing the IP with your host machine's
local IP address:

```bash
wget http://192.168.x.x:8080/your-cert.ovpn
```

Once the download completes, stop the server on your host with `Ctrl+C`.

> Your host's local IP is usually visible in your network settings, or by running
> `ip addr` (Linux/Mac) or `ipconfig` (Windows) on the host.

---

## Connecting to the cyber range network

```bash
sudo openvpn --config your-cert.ovpn
```

Leave this running in a terminal. Once you see `Initialization Sequence Completed`
you're connected.

To verify, try pinging a range host or check that DNS is resolving range hostnames
correctly.

---

## Next steps

With the VM set up and connected to the network, follow the
[Getting Started guide](getting-started.md) to install and launch the toolkit.
