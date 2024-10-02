# HUND IPS FOR EDGEOS

This is a custom IPS solution for EdgeOS routers to block malicious IP adresses as reported by Suricata. 

### How this works?

Suricata alerts need to be pushed to a Redis server under a key named "suricata". The ips.py script needs to run as a daemon and will gather the offending IPs from the Suricata alerts stored in Redis, and will dynamically update an address-list named IP_BLACKLIST on the EdgeOS router using api calls.

### Instruction:

1. Configure a Redis server. No need for something super fancy. I am using a Docker instance running on a Raspberry Pi.
2. Configure Suricata to add an additional eve-log logger instance of type Redis pointing to your Redis server. Use the key name "suricata" and the list mode.
3. On the EdgeRouter, create a firewall address group named "IP_BLACKLIST"
4. Configure your router to deny all incoming traffic from IPs in the IP_BLACkLIST for both WAN_IN and WAN_LOCAL 
5. On the EdgeRouter, add an admin user named "api_user"
6. Customize the script and enter the user assword, redis server information relevant to your setup
7. On the machine with the Redis instance, configure the script to run as a daemon (work in progress, instructions will follow)

### Known issues

1. There is not much of error management in the script at the moment.
2. The blacklist on the router will potentially grow infinitely. You can regularly delete and recreate the list if it becomes too big. Address-groups are limited to ~65000 entries I think
3. The script does an infinite loop and seems to be at times a bit heavy on the resources, to be improved
4. The router admin password is stored in clear text in the source of the script. Make sure to protect it (chmod 700 recommended)
5. By default new found IPs are added to the blacklist every 30 seconds. Be aware that once done any user logged in on the router will be asked to refresh its screen which may be disruptive in case you are in the middle of something.
6. There are probably more issues... 

### Credits
Thanks to [@Benoriusju] for the original script that I have customized to work with EdgeOS api calls.
Thanks to [@Matthew1471] for documenting the EdgeOS API https://github.com/Matthew1471/EdgeOS-API
