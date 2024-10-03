# HUND IPS FOR EDGEOS

This is a custom IPS solution for EdgeOS routers to block malicious IP adresses as reported by Suricata. 

### How this works?

Suricata alerts are pushed to a Redis server under a key named "suricata". The edgeos_ips.py script runs as a daemon and gathers the offending IPs from the Suricata alerts stored in Redis, and dynamically updates an address-group named IP_BLACKLIST on the EdgeOS router using api calls. The address-group is used in firewall rules to block incoming traffic.

### Instructions:

1. Configure a Redis server. No need for something super fancy. I am using a Docker instance (https://hub.docker.com/r/redis/redis-stack which comes with a nice admin interface) running on a Raspberry Pi.
2. Configure Suricata to add an additional eve-log logger instance of type Redis pointing to your Redis server. Use the key name "suricata" and the list mode.
3. On the EdgeRouter, create a firewall address group named "IP_BLACKLIST"
4. Configure your router to deny all incoming traffic from IPs in the IP_BLACkLIST for both WAN_IN and WAN_LOCAL 
5. On the EdgeRouter, add an admin user named "api_user"
6. Customize the script and enter the user password, redis server information relevant to your setup
7. On the machine with the Redis instance (or any other machine that can connect to the Redis server for that matter), copy the script into /usr/local/bin change its owner to a local user and change the permission of the script file to 700
8. Copy the edgeos-ips.service file into /etc/systemd/system, edit the file and change the User= to your local username
9. Reload the services: sudo systemctl daemon-reload
10. Start the edgeos-ips service: sudo service edgeos-ips start

### Known issues

1. There is not much of error management in the script at the moment.
2. The blacklist on the router will potentially grow infinitely. You can regularly delete and recreate the list if it becomes too big. Address-groups are limited to ~65000 entries I think
3. The script does an infinite loop and seems to be at times a bit heavy on the resources, to be improved
4. The router admin password is stored in clear text in the source of the script. Make sure to protect it (chmod 700 recommended)
5. By default new found IPs are added to the blacklist every 30 seconds. Be aware that when the address-group on the router gets updated any logged in user will be asked to refresh their screen which may be disruptive in case you are in the middle of something.
6. There are probably more issues... 

### Credits
Thanks to [@Benoriusju](https://github.com/beinoriusju) for the original script that I have customized to work with EdgeOS api calls.
Thanks to [@Matthew1471](https://github.com/Matthew1471) for documenting the EdgeOS API https://github.com/Matthew1471/EdgeOS-API
