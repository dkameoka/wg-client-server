# Wireguard IPv6 Client Server Configurator Python Script

* Used to set up a partially routed tunnel between server and clients.
* Uses IPv6 for configurations. This reduces network collisions when using multiple VPNs. Tunnel endpoint can be through IPv4, so IPv6 connection is not necessary.
* Great for home servers where family and friends can connect to.
* Low dependencies: Only depends on the base Python 3 install, Wireguard (comes with newer Linux), and optional qrencode.

## Restrictions
* Most cellular service providers and firewalls filter out various ports and traffic (UDP) that Wireguard uses. To get around this, use commonly used ports like 443, 989, and 80 for the server (port forwarding router or OS level pre-routing redirects) and Endpoints. When port forwarding on the server's router, you can forward all of those ports to 51820 towards the server. If that doesn't work to bypass, you may need to tunnel the Wireguard traffic and it may not be worth the hassle.
* Without support for NAT hairpinning, a router won't forward packets with the external destination IP back to the internal network. To get around this, each client device would need a duplicate configuration with one Endpoint set to the internal host and the other for the external host. The client would need to toggle between those configurations as the device transitioned between the internal and external networks like between the home router and coffee shop router.
* An external DNS has to be used for internal IPs for privacy reasons. Using the DNS setting in Wireguard could route all client DNS requests through the server. Duckdns.org is a great solution for this by using it for internal IPs.

## Requires
* All devices support IPv6. IPv6 internet is not required.
* Python 3.
* wg command.
* (Optional) qrencode command for QR encoded configurations.

## Setup
### Generating Configurations
1. Change current working directory (CWD) into the one containing the wgclientserver.py script.
2. Run the following command to generate a single server CSV line. It redirects and overwrites myserver.csv.
```
./wgclientserver.py server > myserver.csv
```
3. Run the following command a bunch of times to generate multiple client CSV lines. It redirects and appends to myclients.csv.
```
./wgclientserver.py client >> myclients.csv
```
4. Edit myserver.csv. The CSV columns are the configuration name, IPv6 network (this is randomized, but can be manually chosen), Endpoint with external port, internal port, private key. The configuration names for both server and client may only contain alpha-numerics and "_=+.-" characters, and must be less than or equal to 15 characters. The IPv6 networks must be Unique Local Addresses (ULA), which start with "fd". It is also best to keep the /48 and /64 used in the next section.
```
wg-name,fd4e:d574:39d0::/48,<domain:443>,51820,OOTIgHhgBQrYTP/5aeV6LLabsMoPciSKarz7E4wNjkE=
```
Example
```
homeserver,fd4e:d574:39d0::/48,homeserver.duckdns.org:989,51820,OOTIgHhgBQrYTP/5aeV6LLabsMoPciSKarz7E4wNjkE=
```
5. Edit myclients.csv. The CSV columns are the configuration name, IPv6 address within the homeserver network (you can separate into different subnets to use with firewalls), persistent keep-alive sent per x seconds (keeps connections from being lost from firewalls/NATs), private key, pre-shared key (more encryption security).
```
client-name,fd::/64,25,AKmMeRA72jiwWPGsDXfDTNISc79KDcdkVHLBlGJDxmc=,H6eTpAPpnkKMXw9yVf6EOYfIi47VbrbrFb2aqu7vtas=
client-name,fd::/64,25,yPZ4LI/kRd2D3enlZKSoc75lc4kYFxgXlQX0HzA2tnA=,S1NCKs9i+Ycfg/Q9kk788kPueuM+pD6sB7wnp+ioas4=
client-name,fd::/64,25,2FCeazhMiZL1GO+IHMVzDgVvsv/rJFZcq0XDZwtAnk8=,GHM1EtQMCYvFzkSPdlnGRz8IvpkUS0fyYkkvqEbwcJI=
client-name,fd::/64,25,KFy3+Q2LTiQ/G5ciVvrArFFFdbpXt73JBXYFT9MMSns=,NyyNX2yrhItvz6y1b0X7hHavlHVMCfqz28QBWgpf44E=
```
Example
```
lead-desktop,fd4e:d574:39d0::1/64,25,AKmMeRA72jiwWPGsDXfDTNISc79KDcdkVHLBlGJDxmc=,H6eTpAPpnkKMXw9yVf6EOYfIi47VbrbrFb2aqu7vtas=
fam-tablet,fd4e:d574:39d0:1::/64/64,25,yPZ4LI/kRd2D3enlZKSoc75lc4kYFxgXlQX0HzA2tnA=,S1NCKs9i+Ycfg/Q9kk788kPueuM+pD6sB7wnp+ioas4=
friend-phone,fd4e:d574:39d0:2::/64,25,2FCeazhMiZL1GO+IHMVzDgVvsv/rJFZcq0XDZwtAnk8=,GHM1EtQMCYvFzkSPdlnGRz8IvpkUS0fyYkkvqEbwcJI=
friend-laptop,fd4e:d574:39d0:2::1/64,25,KFy3+Q2LTiQ/G5ciVvrArFFFdbpXt73JBXYFT9MMSns=,NyyNX2yrhItvz6y1b0X7hHavlHVMCfqz28QBWgpf44E=
```
6. Generate the configurations with the following command. Make sure to include the "." to specify CWD as the output path. If qrencode is installed, it will also generate the QR image files. Configuration files won't be written to if they haven't changed.
```
./wgclientserver.py build . myserver.csv myclients.csv
```
7. Put the generated homeserver.conf on the server in /etc/wireguard/ or equivalent configuration path. Linux command below.
```
sudo mv homeserver.conf /etc/wireguard/
```
8. Enable and activate the wireguard server. Linux Systemd command below.
```
sudo systemctl enable --now wg-quick@homeserver
```
If updating the server's configuration, modify and run the following to update Wireguard's state without interruption. The wg-quick command is used to remove wg-quick options while in a sub-shell and piping it to the wg command.
```
sudo wg syncconf homeserver <(wg-quick strip /etc/wireguard/homeserver.conf)
```
9. Allow Wireguard and the server services through the server's firewall. See my [nftables configuration scripts](https://github.com/dkameoka/nftables-template).
10. Port forward the server's router to forward ports 443, 989, and 80 with UDP traffic towards the server's internal IP with 51820. Below is a diagram.
```
UDP { external:443 -> server-internal-ip:51820 }
UDP { external:989 -> server-internal-ip:51820 }
UDP { external:80 -> server-internal-ip:51820 }
```
11. Securely distribute each user's configuration and QR code image.

