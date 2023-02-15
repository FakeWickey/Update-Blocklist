# Update-Blocklist
Update-Blocklist, an adlist parsing python script.

## How does it work?
The script fetches ad-blocklists from different sources (e.g. [Easylist](https://easylist.to/)), and extracts blockable domains out of them. It then generates a textfile in hosts format, overriding the ip's for those domains. It is used with conjuction of [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) service to block ad domains.

When the dnsmasq daemon is configured for a device or a network, domains containing ads or malware are resolved with a non-existing ip, which prevents ad loading.


## Getting Started
To use the script in this repo, you either need to clone or download this repo onto your machine as shown below;
```bash
git clone https://github.com/FakeWickey/Update-Blocklist.git
```

## Prerequisites
This project is made to be run on linux machines.

To use the script, you have to install the dnsmasq service.
After you have installed dnsmasq, edit the /etc/dnsmasq.conf

Change the following configuration parameters to:

`domain-needed`
Doesn't forward plain names.

`resolv-file=/etc/resolv.dnsmasq.conf`
Makes sure that dnsmasq uses external upstream servers.
Example configuration:
```
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700:1111
```

`addn-hosts=/etc/hosts.adserver`
The script fills the hosts.adserver file with localhost ip's and domains.
dnsmasq reads from /etc/hosts.adserver to resolve domains before asking an upstream server.

## Start dnsmasq
Now, start, check and enable the dnsmasq service with the following commands:
```bash
systemctl start dnsmasq.service
```

```bash
systemctl status dnsmasq.service
```

```bash
systemctl enable dnsmasq.service
```

## Setting up the script to run regularly
/etc/cron.d/update-blocklist
```
*/30 * * * * root /usr/bin/python3 <path_to_update-blocklist_script>
```

## License
This projects code is licensed under the [MIT License](https://opensource.org/licenses/MIT).
