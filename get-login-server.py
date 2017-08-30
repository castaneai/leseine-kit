import urllib.request
import configparser

nfo = configparser.ConfigParser()
with urllib.request.urlopen("http://dl.latale.jp/latale/patch/LaTale-MainServer/Update.NFO") as f:
    nfo_str = f.read().decode("utf-8")
nfo.read_string(nfo_str)
actual_login_ep_str = nfo.get("LoginServer", "1_IP")
print(actual_login_ep_str)