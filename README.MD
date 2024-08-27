# ICMP Redirector

This tool is designed for educational and penetration testing purposes. It performs a simple ICMP redirect attack, which can manipulate the routing behavior of the target system by injecting false routing information into the routing cache. Entries in the routing cache overwrite those in the routing table, until the entries expire. This attack can be used to redirect traffic through an attacker-controlled machine.

## Features
* Sends ICMP redirect packets to the target machine to manipulate its routing table cache.
* CLI Support for pentesting & scripting
* Includes helpful documentation in-line 

## Known protections against ICMP Redirection
    If we spoof redirect packets, but the victim machine has not sent out ICMP packets during the attack, the attack will never be successful. This is because the OS kernel conducts some kind of sanity check before accepting an ICMP redirect packets.
        - SEED Labs – ICMP Redirect Attack Lab

### Known OS Kernel Sanity Checks
    ... the OS kernel conducts some kind of sanity check before accepting an ICMP redirect packets. It verifies whether the ICMP redirect is triggered by [a] packet it sent out ... How strictly the checking is conducted depends on the OS.
       - SEED Labs – ICMP Redirect Attack Lab

This checking is more easily bypassed by sniffing for ICMP traffic and then copying an authentic ICMP packets information. 

* Ubuntu 20.04 
    * The operating system verifies that in the Internet Host header inside the ICMP payload matches the type and the destination IP address of the original packet that triggers the ICMP redirect.

* Ubuntu 22.04 
    * The checking is more strict. The ways it is more strict is unknown.

* Windows 
    * Unknown. Please add sources if you are aware of the behavior or research it yourself.

* MacOS 
    * Unknown. Please add sources if you are aware of the behavior or research it yourself.


## Getting Started
To install 

```pip install -r requirements.txt```

Usage

```python3 icmp_redirect.py --target <target_ip> --destination <destination_ip> --gateway <gateway_ip> --attacker <attacker_ip> [--redirect_code <code>] ``` 

### Parameters
    --target:        The IP address of the target who should add the routing table cache entry.
    --destination:   The IP address of the destination. The target will insert a route for this IP via the attacker.
    --gateway:       The IP address of the gateway we're spoofing as.
    --attacker:      The IP address of the attacker.
    --redirect_code: The redirect code from the ICMP redirect RFC. Supports values 0, 1, 2, and 3. Default is 1 (redirect datagrams for the Host).

### ICMP Redirect Codes
    0: Redirect datagrams for the Network.
    1: Redirect datagrams for the Host (default for this tool).
    2: Redirect datagrams for the Type of Service and Network.
    3: Redirect datagrams for the Type of Service and Host.

## Example
To perform an ICMP redirect attack where the target 192.168.1.2 is tricked into routing packets destined for 192.168.1.100 through the attacker 192.168.1.3 using 192.168.1.1 as the gateway:

```python3 icmp_redirect.py --target 192.168.1.2 --destination 192.168.1.100 --gateway 192.168.1.1 --attacker 192.168.1.3```

## References
* Better spoofing of ICMP host redirect messages with Scapy 
    * http://blog.packetheader.net/2010/06/better-spoofing-of-icmp-host-redirect.html
* ICMP (RFC 792) 
    * https://datatracker.ietf.org/doc/html/rfc792
* 
    * https://seedsecuritylabs.org/Labs_20.04/Files/ICMP_Redirect/ICMP_Redirect.pdf
## License
This tool is provided under the MIT License. See the LICENSE file for details.