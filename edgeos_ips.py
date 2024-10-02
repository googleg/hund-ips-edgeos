import redis
import time
import json
from requests import Request, Session

def block_ips(ip_addresses):
    global edgeos_host
    global edgeos_login
    global edgeos_password
    global set_uri

    # Build URLs for the api calls
    login_url="https://" + edgeos_host + "/"
    set_url="https://" + edgeos_host + set_uri
    
    unique_ips = list(set(ip_addresses))  # Convert list to set to remove duplicates, then back to list
    if unique_ips:  # Only proceed if there are unique IPs to block
        try:
            # login
            s = Session()
            my_data = {"username": edgeos_login, "password": edgeos_password}
            my_headers = {'Host':edgeos_host, 'Content-Type': 'application/x-www-form-urlencoded'}
            req = Request('POST', login_url, data=my_data, headers=my_headers)  
            prepped = req.prepare()
            s.cookies.clear()
            # Perform login, do not follow the 303 redirect, do not check the self-signed certificate
            response = s.send(prepped,allow_redirects=False, verify=False) 
            # capture the content of the X-CSRF-TOKEN cookie to replay as a header for next api calls
            for c in response.cookies:
                if c.name == "X-CSRF-TOKEN":
                    csrf_token = c.value
            # go through the list of IPs and add to the blocklist
            if response.status_code == 303: # 303 means authentication was successful
                for new_ip in unique_ips:
                    print("Adding {} to blacklist...".format(new_ip))
                    my_headers = {'Host':edgeos_host, 'Content-Type': 'raw', 'X-CSRF-TOKEN': csrf_token}
                    # adding the IP to the address-group named IP_BLACKLIST
                    my_data = {'firewall':{'group':{'address-group':{'IP_BLACKLIST':{'address':new_ip}}}}}
                    req = Request('POST', set_url, json=my_data, headers=my_headers)  
                    prepped = s.prepare_request(req)
                    response = s.send(prepped, allow_redirects=False, verify=False)
                    if response.status_code != 200: # HTTP 200 is expected in case of success
                        print("Failed to record IP in blacklist")
                    else:
                        print("Added {} to the blacklist".format(new_ip))
            else:
                print("Failed to login.")
            print("Added {} unique IPs to the blacklist.".format(len(unique_ips)))
        except Exception as e:
            print("Failed to append IPs to blocklist: {}".format(e))
            
# Edgerouter URIs, IP, login and password
edgeos_host = "IP_OF_YOUR_ROUTER"
edgeos_login = "api_user"
edgeos_password = "CHANGE_PASSWORD"
set_uri = "/api/edge/set.json"

# Connect to Redis
# My REDIS instance is running on the localhost as a docker container listening on 6380
redis_host = "127.0.0.1"
redis_port = 6380
r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

# The redis key, as configured in the suricata.yaml
list_key = 'suricata'
batch_time = 30  # Batch processing interval in seconds

try:
    ip_batch = []
    last_time = time.time()
    
    while True:
        if (time.time() - last_time) >= batch_time and len(ip_batch):
            block_ips(ip_batch)
            ip_batch = []  # Clear the current batch
            last_time = time.time()  # Reset timer after processing

        log = r.blpop(list_key, timeout=1)  # Short timeout for blpop
        if log:
            # Get the source IP from the suricata alert -> isolate src_ip from the json object
            my_json=json.loads(log[1])
            ip_found=my_json["src_ip"]
            # Only process it if not an IP on the local LAN
            if (ip_found) and (not ip_found.startswith("192.168.")) and (not ip_found.startswith("10.")):
                ip_batch.append(ip_found)
                print("Queued IP for blocking: {}".format(ip_found))
                # tempo à virer
                # block_ips(ip_batch)
                # fin tempo
            else:
                print("No IP found")
            #exit()

except KeyboardInterrupt:
    print("Stopped by the user.")
    if ip_batch:  # Ensure to block remaining IPs before exiting
        block_ips(ip_batch)
except Exception as e:
    print("An error occurred: {e}")
