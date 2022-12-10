# Malcolm [![Generic badge](https://img.shields.io/badge/version-0.8.2-green.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/distro-linux-green.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/language-c-orange.svg)](https://shields.io/)

<p align="center">
  <img src="docs/main.png">
</p>  

Perform a __man in the middle attack__ in __C__ without the help of any network library.

## Summary
* [Introduction](#introduction)
* [Features](#features)
* [Options](#options)
* [Installation](#installation)
* [Usage](#usage)
* [Examples](#examples)
* [Compatibility](#compatibility)
* [Authors](#authors)
* [Disclaimer](#disclaimer)

## Introduction
ARP Poisoning is a type of Man-in-the-Middle (MitM) attack, that __allows hackers to spy on communications between two parties over a Local Area Network (LAN).__  
 *ft_malcolm* is a low-level networking project from 42 (https://42.fr), we went far beyond the subject and implemented a lot of extra features.

## Features
- Multiple modes:
    * __Default__: Specified hosts will be spoofed persistently and redirect their packets to us.
      * `ft_malcolm [Source IP] [Target IP] [Interface] [Options]`
    * __Broadcast__: Spoof all the machines within the LAN.
      * `ft_malcolm --broadcast [Source IP] [Interface] [Options]`
    * __Manual__: You have control over MAC addresses by specifying them
      * `ft_malcolm --manual [Source IP] [Source MAC] [Target IP] [Target MAC] [Options]`
- Denial of Service (DoS) Attack:
    * Paralyse the targets by specifying the *--deny* option.
    * Can be used within the _broadcast_ mode to **paralyse the whole network.**
- Sniffer _(still work in progress)_:
    * Create a sniffer *thread* that __displays your target's activities__ on the network.
- Cache restoration:
    * Once done, malcolm will __restore__ ARP cache of the targets so the network will __work normally again.__

  
## Options
* `-d --duration [time (in seconds)]: Duration of the spoofing process`
* `-f --frequency [Time]: Select (in seconds) the rate for ARP replies`
* `-v --verbose: Displays informations about what ft_malcolm is doing`
* `-h --help: Display the help menu`
* `-V --version: Output the current version of this software`

## Installation
Run `make` to compile the project, make will compile the binary `ft_malcolm`.

## Usage
Since malcolm has a lot of options, run `./ft_malcolm -h` to display the help menu.  
Be sure to run `ft_malcolm` under **root's** privileges.
- __Default mode__  
  `ft_malcolm [Source IP] [Target IP] [Interface] [Options]`
- __Broadcast mode__  
  `ft_malcolm --broadcast [Source IP] [Interface] [Options]`
- __Manual mode__  
  `ft_malcolm --manual [Source IP] [Source MAC] [Target IP] [Target MAC] [Options]`  

### Formatting:
  - __IPv4__ addresses must be valid IPs under this format: `172.17.0.1`  
  - __Hardware addresses__ must be valid MACs under this format: `12:34:56:78:9a:bc`

## Examples
Here are some usage examples for malcolm
- `sudo ./ft_malcolm --manual 172.17.0.1 66:66:66:66:66:66 172.17.0.2 02:42:ac:11:00:02 --no-persistency`
- `sudo ./ft_malcolm 172.17.0.2 172.17.0.3 docker0`
- `sudo ./ft_malcolm 172.17.0.1 eth0 -b --deny -d 20 --frequency 1 -v`
- `sudo ./ft_malcolm --manual 172.17.0.1 66:66:66:66:66:66 172.17.0.2 02:42:ac:11:00:02 --duration 5 --verbose`
- `sudo ./ft_malcolm 172.17.0.1 eth0 -b -s`

## Compatibility
This project is only compatible with Linux.

## Authors
* Ludovic Menthiller (https://github.com/lumenthi)
* Lucas Nicosia (https://github.com/lnicosia)

## Disclaimer
This tool is meant for **educational** only.  
It is your responsibility to make sure you have permission from the network owner before running this tool against it.  
The authors of this tool are **not** responsible for your personal actions or choices.
