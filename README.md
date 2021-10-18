# nereus
 
This app will upload a Let's Encrypt certificate to a PaloAlto Networks firewall that can be used for Management or the GlobalProtect VPN Portal/Gateway.

### Configuration
The configuration can be found in __nereus.yml__ and it is pretty self-explanatory.

* api -> key: the API key generated from the firewall
* api -> mgt_url: the API endpoint of the firewall
* certificate -> key: the full path to the private key file (MUST not have a password set)
* certificate -> fullchain: the full path to the fullchain certificate file
* certificate -> name: how PAN will name this certificate

#### Notes:
- The current version only uploads a single certificate/key pair
- There's a chance that not all errors are caught and treated
- It should work with other certificate providers, assuming you follow the same format as the LE ones (chain in one file and a separate key file with no password in another file)
