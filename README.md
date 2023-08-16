# go-kdcproxy

This is a Go based KDC Proxy designed for use against Active Directory.

# Status

It works for me.

Please note that the service only uses TCP to communicate with KDC's and assumes DNS SRV records are in place for KDC discovery.

# Specifications

This service follows the MS-KKDCP specification that is published here:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38

# Credits

This was initially based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw

In addition a lot of the logic for the service to make things work came from:

https://github.com/latchset/kdcproxy
