# cloudflare-WAF-Setup
CF API credentials are stored locally in a JSON file. if it does not exist, the tool will prompt you for the API details

Prior to applying WAF rules, the zones must be selected. 


## Usage

1. **Setup API Credetials**

```sh
python cloudflare_waf.py --setup
``` 

2. **List available Cloudflare zones**

```sh
python cloudflare_waf.py --list-zones
``` 
   
3. **Apply WAF rules to selected zones**
A backup of the existing rule set is stored in backup.json

```sh
python cloudflare_waf.py --apply-rules
```

4. **Restore backup**
Previous rules can be restored in case of problems with the new rule set

```sh
python cloudflare_waf.py --restore
```

4. **Delete stored credentials**

```sh
python cloudflare_waf.py --clear
```
