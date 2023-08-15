# go-kdcproxy

This is an attempt to build a KDC Proxy using Golang based on the implementation here:

https://github.com/bolkedebruin/rdpgw

# Status

This does NOT work currently. 

# Specifications

This service follows the MS-KKDCP specification that is published here:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38

This service does deviate from the specification in that it does not verify that KDC_PROXY_MESSAGE.kerb-message is a well-formed Kerberos message, it simply forwards it onto the KDC (or it would if the realm was correctly extracted from the incoming KDC_PROXY_MESSAGE).

# Credits

As noted above, this is based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw
