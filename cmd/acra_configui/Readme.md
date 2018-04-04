# About AcraConfigUI
AcraConfigUI is a lightweight HTTP web server for managing AcraServer's certain configuration options.
The interface of AcraConfigUI consists of the following elements:
 
* **AcraServer Settings** — managing AcraServer's settings.
* **Firewall** (Coming soon) — Firewall/Intrusion detection settings.
* **Zones** (Coming soon) — managing Zone keys.
# Setup
* [Build the AcraServer environment](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#build-the-key-generator-and-generate-keys)
* Get and build AcraConfigUI.
```
go get github.com/cossacklabs/acra/cmd/acra_configui
```
*  AcraConfigUI uses HTTP API requests to get data from AcraServer and to change its settings. Using CLI-parameters (--acra_host, --acra_port), you can point it to AcraServer.
*  By default, AcraConfigUI accepts requests at localhost:8000. Use `--host` and `--port` to change this default preset.
 
You can make an SSH-tunnel to gain access to the remote port:
```
ssh -L8000:localhost:8000 <acraserver>
```
* To provide additional security, AcraConfigUI uses basic authentication. Its control option is *--auth_mode*. Possible values:
  * auth_on — basic authentication is on (default).
  * auth_off_local — basic authentication is on for non-local requests (out of the range of 127.0.0.1/localhost).
  * auth_off — basic authentication is turned off.
  
Users/passwords are stored in an encrypted file and are managed by *acra_genauth* utility:
  
```go get github.com/cossacklabs/acra/cmd/acra_genauth```
  
To add user/password:  
```
cd $GOPATH
$GOPATH/bin/acra_genauth --set --user=&lt;user&gt; --pwd=&lt;password&gt;
```
To remove user/password:
```
cd $GOPATH
$GOPATH/bin/acra_genauth --remove --user=&lt;user&gt;
```
  
Encrypted user/password-storage is stored in ```config/auth.keys```, use `--file` to change this.
  
> Note: We encrypt auth the storage with .acrakeys/auth_key that is auto-generated at the first run of acra_genauth. It can be recreated manually through  
```$GOPATH/bin/acra_genauth --basicauth```.
 
 > Be careful as this will discard the old storage file and you will need to setup the users/passwords again!
# Usage
Open the AcraConfigUI HTTP endpoint in your browser.
In **AcraServer settings** you can save settings — AcraServer will be gracefully restarted while applying new options via a config file. AcraConfigUI rewrites config file with new values.

**Note**. If you want to use AcraConfigUI's *AcraServer settings* you should avoid using command line options for AcraServer as they have higher priority than the config file.
