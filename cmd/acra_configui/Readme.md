# About AcraConfigUI
AcraConfigUI is a lighweight HTTP web server to manage Acraserver's certain configuration options.
 Its interface consists of the following areas:
 
* **AcraServer Settings** - for Acraserver's settings managment
* **Intrusion Detection** (Coming soon) - for Firewall/Intrusion detection settings
* **Zones** (Coming soon) - for zone keys managment

# Setup


# Usage
Just open AcraConfigUI HTTP endpoint in your browser.
At **AcraServer settings** you can save settings - Acraserver will be gracefully restarted applying new options. AcraConfigUI simply rewrites config file with new settings.
**Note** If you want to use AcraConfigUI you should avoid using command line options for Acraserver as they have higher priority over config. 
