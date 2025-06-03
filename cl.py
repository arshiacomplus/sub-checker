import os
import sys
import requests
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, wait
import psutil
import time
import json
from retrying import retry
from requests import RequestException
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass,field
from json import JSONEncoder
import yaml
import logging
import base64
import urllib.parse
import urllib.request
import signal
os.system("chmod +x hy2/hysteria")
IPDATA_API_KEY = "45d33281a59a93aeb7227414b15038f7a5a591c7e68962aa1c37d159"
TH_MAX_WORKER=5
CONF_PATH="config.json"
with open(CONF_PATH,"r") as file_client_set:
        f=json.load(file_client_set)
        test_link_=f["core"]["test_url"]
TEXT_PATH="normal.txt"
LINK_PATH=[] # [ "link1" , "link2" , ... ]
FIN_PATH="final.txt"
FIN_CONF=[]
CHECK_LOC=True
CHECK_IRAN=True
CHECK_HOST_IRANIAN_NODES = [
    "ir1.node.check-host.net",  # Tehran, AS44244 Mobile Communication Company of Iran (MCI)
    "ir2.node.check-host.net",  # Tehran, AS12880 Telecommunication Infrastructure Company (TIC زیرساخت)
    "ir3.node.check-host.net",  # Tehran, AS58224 Rightel
]
def remove_empty_strings(input_list):
    return [item for item in input_list if item and item != "\n" ]
with open(TEXT_PATH,"r") as f:
    conf=remove_empty_strings(f.readlines())
class ProcessManager:
    """
    Manages background processes (like Xray, Hysteria) started by the script.
    Ensures proper termination on Linux systems using SIGTERM and SIGKILL.
    """
    def __init__(self):
        self.active_processes = {}
        self.lock = threading.Lock()
        print("ProcessManager initialized.")
    def add_process(self, name: str, pid: int):
        """یک پردازش جدید را به لیست مدیریت‌شده اضافه می‌کند."""
        with self.lock:
            if name in self.active_processes:
                print(f"Warning: Process name '{name}' already exists with PID {self.active_processes[name]}. Overwriting with new PID {pid}.")
            print(f"Tracking process '{name}' with PID {pid}.")
            self.active_processes[name] = pid
    def stop_process(self, name: str):
        """یک پردازش مشخص را با نام آن متوقف می‌کند."""
        pid_to_stop = None
        with self.lock:
            if name in self.active_processes:
                pid_to_stop = self.active_processes.pop(name)
                print(f"Attempting to stop process '{name}' with PID {pid_to_stop}. Removed from tracking list.")
            else:
                print(f"Process '{name}' not found in active processes list for stopping.")
                return
        if pid_to_stop is None:
             print(f"Error: Could not retrieve PID for '{name}' despite being found initially.")
             return
        try:
            if psutil.pid_exists(pid_to_stop):
                print(f"  Sending SIGTERM (polite request) to PID {pid_to_stop}...")
                os.kill(pid_to_stop, signal.SIGTERM)
                time.sleep(1)
                if psutil.pid_exists(pid_to_stop):
                    print(f"  PID {pid_to_stop} still exists after SIGTERM. Sending SIGKILL (force kill)...")
                    os.kill(pid_to_stop, signal.SIGKILL)
                    time.sleep(0.1)
                    if psutil.pid_exists(pid_to_stop):
                        print(f"  WARNING: PID {pid_to_stop} could not be terminated even with SIGKILL!")
                    else:
                        print(f"  PID {pid_to_stop} terminated successfully by SIGKILL.")
                else:
                    print(f"  PID {pid_to_stop} terminated gracefully by SIGTERM.")
            else:
                print(f"  Process with PID {pid_to_stop} was already gone before stop attempt.")
        except (ProcessLookupError, psutil.NoSuchProcess):
            print(f"  Process with PID {pid_to_stop} disappeared during termination attempt.")
        except PermissionError:
            print(f"  ERROR: Permission denied to send signal to PID {pid_to_stop}.")
        except Exception as e:
            print(f"  ERROR: An unexpected error occurred while stopping PID {pid_to_stop}: {e}")
    def stop_all(self):
        """تمام پردازش‌های مدیریت‌شده را متوقف می‌کند."""
        print("Stopping all tracked processes...")
        names_to_stop = []
        with self.lock:
             names_to_stop = list(self.active_processes.keys())
        if not names_to_stop:
            print("No active processes were being tracked.")
            return
        print(f"Found {len(names_to_stop)} processes to stop: {names_to_stop}")
        for name in names_to_stop:
             self.stop_process(name)
        print("Finished stopping all tracked processes.")
process_manager = ProcessManager()
xray_abs="xray/xray"
def parse_configs(conifg,num=0,cv=1,hy2_path="hy2/config.yaml",is_hy2=False): # nuitka: pragma: no cover
    @dataclass
    class ConfigParams:
        protocol: str
        address: str
        port: int
        security: Optional[str] = ""
        encryption: Optional[str] = "none"
        header_type: Optional[str] = "none"
        network: Optional[str] = "tcp"
        flow: Optional[str] = ""
        sni: Optional[str] = ""
        fp: Optional[str] = ""
        alpn: Optional[str] = None
        pbk: Optional[str] = ""
        sid: Optional[str] = ""
        spx: Optional[str] = ""
        tag: Optional[str] = ""
        id: Optional[str] = ""
        type: Optional[str] = "tcp"
        alter_id: Optional[str] = ""
        mode: Optional[str] = None
        host: Optional[str] = None
        path: Optional[str] = None
        scy: Optional[str] = ""
        socks_user: Optional[str] = ""
        ss_method: Optional[str] = "chacha20-poly1305"
        ss_password: Optional[str] = ""
        hy2_insecure: Optional[str] = "0"
        hy2_obfs_password: Optional[str] = ""
        hy2_hop_interval: Optional[str] = "30"
        hy2_pinsha256: Optional[str] = ""
        hy2_obfs: Optional[str] = ""
        wg_reserved: Optional[str] = ""
        wg_public_key: Optional[str] = ""
        wg_endpoint: Optional[str] = ""
        wg_secret_key: Optional[str] = ""
        wg_keep_alive: Optional[int] = 10
        wg_mtu: Optional[int] = 0
        wg_address: Optional[str] = ""
        wnoise: Optional[str] = "quic"
        wnoisecount: Optional[str] = "15"
        wnoisedelay: Optional[str] = "1-3"
        wpayloadsize: Optional[str] = "1-8"
        extra_params: Dict[str, Any] = field(default_factory=dict)
    def parse_configs_by_get(config: str) -> ConfigParams:
        """Parse all possible parameters from config strings"""
        try:
            config = config.strip()
            config = urllib.parse.unquote(config)
            config_parts = config.split('#', 1)
            main_config = config_parts[0]
            print(config_parts)
            tag = urllib.parse.unquote(config_parts[1]) if len(config_parts) > 1 else ""
            protocol = next((p for p in ["vless", "vmess", "trojan", "hy2", "hysteria2",
                                        "ss", "socks", "wireguard"] if main_config.startswith(p+ "://")), None)
            if not protocol:
                raise ValueError("Invalid protocol")
            common_params = {"protocol": protocol, "tag": tag}
            if protocol in ["vless", "trojan"]:
                match = re.search(r'([^:]+)@([^:]+):(\d+)', main_config)
                if match:
                    common_params.update({
                        "id": match.group(1).replace("//","") if protocol != "trojan" else "",
                        "address": match.group(2),
                        "port": int(match.group(3))
                    })
            elif protocol == "wireguard":
                match = re.search(r'([^@]+)@([^:]+):(\d+)', main_config)
                if match:
                    common_params.update({
                        "wg_secret_key": match.group(1).split('wireguard://')[1],
                        "address": match.group(2),
                        "port": int(match.group(3))
                    })
            elif protocol in ["hy2", "hysteria2"]:
                    match = re.search(rf"{protocol}://([^@]+)@([^:/?#]+):(\d+)", main_config)
                    if match:
                        common_params.update(
                            {
                                "ss_password": match.group(1),
                                "address": match.group(2),
                                "port": int(match.group(3)),
                            }
                        )
            else:
                match = re.search(r'@([^:]+):(\d+)', main_config)
                if match:
                    common_params.update({
                        "address": match.group(1),
                        "port": int(match.group(2))
                    })
            protocol_handlers = {
                "vless": parse_vless,
                "vmess": parse_vmess,
                "trojan": parse_trojan,
                "hy2": parse_hysteria,
                "hysteria2": parse_hysteria,
                "ss": parse_shadowsocks,
                "socks": parse_socks,
                "wireguard": parse_wireguard
            }
            parser = protocol_handlers.get(protocol)
            if not parser:
                raise NotImplementedError(f"Unsupported protocol: {protocol}")
            return parser(main_config, common_params)
        except Exception as e:
            logging.error(f"Error parsing config: {e}")
            return ConfigParams(protocol="", address="", port=0)
    def parse_vless(config: str, common: dict) -> ConfigParams:
        query = re.split(r"\?", config, 1)[1] if "?" in config else ""
        params = parse_query_params(query)
        host_params = {
            "tcp": params.get("host",None),
            "ws": params.get("host",None),
            "h2": params.get("host",None),
            "httpupgrade": params.get("host",None),
            "xhttp": params.get("host",None),
            "splithttp": params.get("host",None),
            "quic": params.get("quicSecurity", None),
            "grpc": params.get("authority", None)
        }
        path_params = {
            "ws": params.get("path",None),
            "h2": params.get("path",None),
            "httpupgrade": params.get("path",None),
            "splithttp": params.get("path",None),
            "xhttp": params.get("path",None),
            "kcp": params.get("seed", None),
            "grpc": params.get("serviceName",None),
            "quic": params.get("key",None)
        }
        return ConfigParams(
            **common,
            security=params.get("security", ""),
            encryption=params.get("encryption", "none"),
            type=params.get("type", "tcp"),
            host=host_params.get(params.get("type", "tcp"), None),
            path=path_params.get(params.get("type", "tcp"), None),
            flow=params.get("flow", ""),
            sni=params.get("sni", ""),
            fp=params.get("fp", ""),
            alpn=params.get("alpn", None),
            pbk=params.get("pbk", ""),
            sid=params.get("sid", ""),
            spx=params.get("spx", ""),
            mode=params.get("mode", None)
        )
    def parse_vmess(config: str, common: dict) -> ConfigParams:
        encoded_part = config.split("://")[1]
        missing_padding = len(encoded_part) % 4
        if missing_padding:
            encoded_part += '=' * (4 - missing_padding)
        decoded = base64.b64decode(encoded_part).decode("utf-8")
        vmess_data = json.loads(decoded)
        address = vmess_data.get("add", "")
        port = int(vmess_data.get("port", 0))
        tag = vmess_data.get("ps", "none")
        sec=vmess_data.get("tls", "")
        return ConfigParams(
            protocol=common.get("protocol",""),
            address=address,
            port=port,
            tag=tag,
            security=sec,
            id=vmess_data.get("id", ""),
            alter_id=int(vmess_data.get("aid", 0)),
            scy=vmess_data.get("scy", ""),
            sni=vmess_data.get("sni", ""),
            fp=vmess_data.get("fp", ""),
            type=vmess_data.get("net","tcp"),
            host=vmess_data.get("host", None),
            path=vmess_data.get("path", None),
            alpn=vmess_data.get("alpn", None),
            mode=vmess_data.get("mode", None)
        )
    def parse_trojan(config: str, common: dict) -> ConfigParams:
        query = re.split(r"\?", config, 1)[1] if "?" in config else ""
        params = parse_query_params(query)
        password = re.search(r'trojan://([^@]+)@', config).group(1) if "trojan://" in config else ""
        host_params = {
            "tcp": params.get("host",None),
            "ws": params.get("host",None),
            "h2": params.get("host",None),
            "httpupgrade": params.get("host",None),
            "xhttp": params.get("host",None),
            "splithttp": params.get("host",None),
            "quic": params.get("quicSecurity", None),
            "grpc": params.get("authority", None)
        }
        path_params = {
            "ws": params.get("path",None),
            "h2": params.get("path",None),
            "httpupgrade": params.get("path",None),
            "splithttp": params.get("path",None),
            "xhttp": params.get("path",None),
            "kcp": params.get("seed", None),
            "grpc": params.get("serviceName",None),
            "quic": params.get("key",None)
        }
        return ConfigParams(
            **common,
            security="tls",
            ss_password=password,
            sni=params.get("sni", ""),
            fp=params.get("fp", ""),
            alpn=params.get("alpn", None),
            pbk=params.get("pbk", ""),
            sid=params.get("sid", ""),
            type=params.get("type", "tcp"),
            host=host_params.get(params.get("type", "tcp"), None),
            path=path_params.get(params.get("type", "tcp"), None),
            spx=params.get("spx", ""),
            mode=params.get("mode", None)
        )
    def parse_hysteria(config: str, common: dict) -> ConfigParams:
        query = re.split(r"\?", config, 1)[1] if "?" in config else ""
        params = parse_query_params(query)
        print(params.get("obfs-password", ""))
        return ConfigParams(
            **common,
            security="tls",
            hy2_insecure=params.get("insecure", "0") == "1",
            hy2_obfs_password=params.get("obfs-password", ""),
            hy2_hop_interval=int(params.get("hopInterval", 30)),
            hy2_pinsha256=params.get("pinSHA256", ""),
            hy2_obfs=params.get("obfs", ""),
            sni=params.get("sni", common.get("address","")),
            alpn=params.get("alpn", None),
        )
    def parse_socks(config: str, common: dict) -> ConfigParams:
        auth_part = config.split("://")[1].split("@")[0]
        user_pass = base64.b64decode(auth_part).decode("utf-8").split(":")
        return ConfigParams(
            **common,
            socks_user=user_pass[0],
            ss_password=user_pass[1],
            security="none"
        )
    def parse_wireguard(config: str, common: dict) -> ConfigParams:
        query = re.split(r"\?", config, 1)[1] if "?" in config else ""
        params = parse_query_params(query)
        return ConfigParams(
            **common,
            wg_reserved=params.get("reserved", ""),
            wg_public_key=params.get("publickey", ""),
            wg_endpoint=params.get("endpoint", ""),
            wg_keep_alive=int(params.get("keepalive", 5)),
            wg_mtu=int(params.get("mtu",0)),
            wg_address=params.get("address",""),
            wnoise=params.get("wnoise", "quic"),
            wnoisecount=params.get("wnoisecount", "15"),
            wnoisedelay=params.get("wnoisedelay", "1-3"),
            wpayloadsize=params.get("wpayloadsize", "1-8")
        )
    def parse_shadowsocks(config: str, common: dict) -> ConfigParams:
        main_part = config.split("ss://", 1)[1].split("#", 1)[0]
        ss_method = "chacha20-poly1305"
        ss_password = ""
        address = common.get("address", "")
        port = common.get("port", 0)
        try:
            if "@" in main_part:
                parts = main_part.split("@", 1)
                auth_encoded = parts[0]
                server_info = parts[1]
                auth_decoded_bytes = base64.b64decode(auth_encoded)
                auth_decoded_str = auth_decoded_bytes.decode("utf-8")
                method_pass_parts = auth_decoded_str.split(":", 1)
                if len(method_pass_parts) == 2:
                    ss_method = method_pass_parts[0]
                    ss_password = method_pass_parts[1]
                else:
                    logging.warning(f"SS: Auth part '{auth_decoded_str}' not in 'method:pass' format. Using defaults or what's available.")
                    if ":" not in auth_decoded_str and auth_decoded_str:
                        ss_password = auth_decoded_str
                if ":" in server_info:
                    server_parts = server_info.rsplit(":", 1)
                    address = server_parts[0]
                    try:
                        port = int(server_parts[1])
                    except ValueError:
                        logging.error(f"SS: Invalid port in server_info: {server_info}")
                        return ConfigParams(protocol=common.get("protocol", "ss"), address="", port=0, tag=common.get("tag", "PARSE_ERROR_SS"))
                else:
                    address = server_info
                    logging.warning(f"SS: Port not found in server_info: {server_info}. Using port from common if available.")
            else:
                decoded_bytes = base64.b64decode(main_part)
                decoded_str = decoded_bytes.decode("utf-8")
                if "@" in decoded_str:
                    auth_part_decoded, server_info_decoded = decoded_str.split("@", 1)
                    method_pass_parts = auth_part_decoded.split(":", 1)
                    if len(method_pass_parts) == 2:
                        ss_method = method_pass_parts[0]
                        ss_password = method_pass_parts[1]
                    else:
                        logging.warning(f"SS (Full Base64): Auth part '{auth_part_decoded}' not in 'method:pass' format.")
                        if ":" not in auth_part_decoded and auth_part_decoded:
                            ss_password = auth_part_decoded
                    if ":" in server_info_decoded:
                        server_parts = server_info_decoded.rsplit(":", 1)
                        address = server_parts[0]
                        try:
                            port = int(server_parts[1])
                        except ValueError:
                            logging.error(f"SS (Full Base64): Invalid port in server_info_decoded: {server_info_decoded}")
                            return ConfigParams(protocol=common.get("protocol", "ss"), address="", port=0, tag=common.get("tag", "PARSE_ERROR_SS_FULLB64"))
                    else:
                        address = server_info_decoded
                        logging.warning(f"SS (Full Base64): Port not found in server_info_decoded: {server_info_decoded}. Using default port 0.")
                        port = 0
                else:
                    logging.error(f"SS: Decoded string '{decoded_str}' from full Base64 is not in 'auth@server:port' format.")
                    return ConfigParams(protocol=common.get("protocol", "ss"), address="", port=0, tag=common.get("tag", "PARSE_ERROR_SS_MALFORMED_B64"))
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            logging.error(f"SS: Base64 decoding error for '{main_part[:50]}...': {e}")
            return ConfigParams(protocol=common.get("protocol", "ss"), address="", port=0, tag=common.get("tag", "PARSE_ERROR_SS_B64DEC"))
        except Exception as e:
            logging.error(f"SS: Unexpected error parsing shadowsocks config '{config[:50]}...': {e}")
            return ConfigParams(protocol=common.get("protocol", "ss"), address="", port=0, tag=common.get("tag", "PARSE_ERROR_SS_UNEXPECTED"))
        plugin_params = {}
        if "?" in config:
            query_str = config.split("?", 1)[1].split("#", 1)[0]
            plugin_params = parse_query_params(query_str)
        final_params = {
            **common,
            "ss_method": ss_method,
            "ss_password": ss_password,
            "address": address,
            "port": port,
            "security": "none",
        }
        return ConfigParams(**final_params)
    def parse_query_params(query: str) -> Dict[str, str]:
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = urllib.parse.unquote(value)
        return params
    conifg=urllib.parse.unquote(conifg)
    dict_conf=parse_configs_by_get(conifg)
    print("the cv is"+ str(cv))
    LOCAL_HOST="127.0.0."+str(cv)
    DEFAULT_PORT = 443
    DEFAULT_SECURITY = "auto"
    DEFAULT_LEVEL = 8
    DEFAULT_NETWORK = "tcp"
    TLS = "tls"
    REALITY = "reality"
    HTTP = "http"
    try:
        with open(CONF_PATH,"r") as f:
            file=json.load(f)
        core=file['core']
        warp_sets = file['warp_on_warp']
        fragment_sets=core["fragment"]
        fake_host_sets =core["fake_host"]
        mux_sets= core["mux"]
        dns_sets = core["dns"]
        routing_sets = core["routing_rules"]
        inbound_ports = core["inbound_ports"]
        PACKETS=fragment_sets["packets"]
        LENGTH=fragment_sets["length"]
        INTERVAL=fragment_sets["interval"]
        FAKEHOST_ENABLE= fake_host_sets["enabled"]
        HOST1_DOMAIN=fake_host_sets["domain"]
        HOST2_DOMAIN=HOST1_DOMAIN
        MUX_ENABLE= mux_sets["enabled"]
        CONCURRENCY=mux_sets["concurrency"]
        FRAGMENT= fragment_sets["enabled"]
        IS_WARP_ON_WARP= warp_sets["enabled"]
        WARPONWARP=urllib.parse.unquote(warp_sets["config_url"])
        ENABLELOCALDNS = dns_sets["enabled"]
        ENABLEFAKEDNS = dns_sets["fake_dns_enabled"]
        LOCALDNSPORT = dns_sets["local_port"]
        ALLOWINCREASE = core["allow_insecure_tls"]
        DOMAINSTRATEGY = core["domain_strategy"]
        CUSTOMRULES_PROXY = routing_sets["proxy"].split(",")
        CUSTOMRULES_DIRECT = routing_sets["direct"].split(",")
        CUSTOMRULES_BLOCKED = routing_sets["block"].split(",")
        SOCKS5 = inbound_ports["socks"]
        HTTP5 = inbound_ports["http"]
        REMOTEDNS = dns_sets["remote_server"]
        DOMESTICDNS = dns_sets["domestic_server"]
        LOGLEVEL = core["log_level"]
        SNIFFING = core["sniffing_enabled"]
    except Exception as E:
        print(E)
    is_warp=False
    class V2rayConfig:
        def __init__(self, remarks: Optional[str] = None, stats: Optional[Any] = None, log: 'LogBean' = None,
                    policy: Optional['PolicyBean'] = None, inbounds: List['InboundBean'] = None,
                    outbounds: List['OutboundBean'] = None, dns: 'DnsBean' = None, routing: 'RoutingBean' = None,
                    api: Optional[Any] = None, transport: Optional[Any] = None, reverse: Optional[Any] = None,
                    fakedns: Optional[Any] = None, browserForwarder: Optional[Any] = None,
                    observatory: Optional[Any] = None, burstObservatory: Optional[Any] = None):
            self.remarks = remarks
            self.stats = stats
            self.log = log
            self.policy = policy
            self.inbounds = inbounds if inbounds is not None else None
            self.outbounds = outbounds if outbounds is not None else None
            self.dns = dns
            self.routing = routing
            self.api = api
            self.transport = transport
            self.reverse = reverse
            self.fakedns = fakedns
            self.browserForwarder = browserForwarder
            self.observatory = observatory
            self.burstObservatory = burstObservatory
        class LogBean:
            def __init__(self, access: str, error: str, loglevel: Optional[str] = None, dnsLog: Optional[bool] = None):
                self.access = access
                self.error = error
                self.loglevel = loglevel
                self.dnsLog = dnsLog
        class InboundBean:
            def __init__(self, tag: str, port: int, protocol: str, listen: Optional[str] = None, settings: Optional[Any] = None,
                        sniffing: Optional['V2rayConfig.InboundBean.SniffingBean'] = None, streamSettings: Optional[Any] = None, allocate: Optional[Any] = None):
                self.tag = tag
                self.port = port
                self.protocol = protocol
                self.listen = listen
                self.settings = settings
                self.sniffing = sniffing
                self.streamSettings = streamSettings
                self.allocate = allocate
            class InSettingsBean:
                def __init__(self, auth: Optional[str] = None, udp: Optional[bool] = None,allowTransparent: Optional[bool] = None, userLevel: Optional[int] = None,
                            address: Optional[str] = None, port: Optional[int] = None, network: Optional[str] = None):
                    self.auth = auth
                    self.udp = udp
                    self.userLevel = userLevel
                    self.address = address
                    self.port = port
                    self.network = network
                    self.allowTransparent=allowTransparent
            class SniffingBean:
                def __init__(self, enabled: bool, destOverride: List[str], metadataOnly: Optional[bool] = None, routeOnly: Optional[bool] = None):
                    self.enabled = enabled
                    self.destOverride = destOverride
                    self.metadataOnly = metadataOnly
                    self.routeOnly = routeOnly
        @dataclass
        class OutboundBean:
            def __init__(self, tag: str = "proxy", protocol: str = "", settings: Optional['V2rayConfig.OutboundBean.OutSettingsBean'] = None,
                        streamSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean'] = None, proxySettings: Optional[Any] = None,
                        sendThrough: Optional[str] = None, mux: 'V2rayConfig.OutboundBean.MuxBean' = None):
                self.tag = tag
                self.protocol = protocol
                self.settings = settings
                self.streamSettings = streamSettings
                self.proxySettings = proxySettings
                self.sendThrough = sendThrough
                self.mux = mux if mux is not None else self.MuxBean(False)
            class BeforeFrgSettings:
                def __init__(self,tag:Optional[str] = None,protocol:Optional[str]="freedom",settings:Optional['V2rayConfig.OutboundBean.OutSettingsBean.FragmentBean']=None,streamSettings:Optional['V2rayConfig.OutboundBean.StreamSettingsBean'] = None) :
                    self.tag=tag
                    self.protocol=protocol
                    self.settings=settings
                    self.streamSettings=streamSettings
            class OutSettingsBean:
                def __init__(self, vnext: Optional[List['V2rayConfig.OutboundBean.OutSettingsBean.VnextBean']] = None,
                            fragment: Optional['V2rayConfig.OutboundBean.OutSettingsBean.FragmentBean'] = None,
                            noises: Optional[List['V2rayConfig.OutboundBean.OutSettingsBean.NoiseBean']] = None,
                            servers: Optional[List['V2rayConfig.OutboundBean.OutSettingsBean.ServersBean']] = None,
                            response: Optional['V2rayConfig.OutboundBean.OutSettingsBean.Response'] = None,
                            network: Optional[str] = None, address: Optional[Any] = None, port: Optional[int] = None,
                            domainStrategy: Optional[str] = None, redirect: Optional[str] = None, userLevel: Optional[int] = None,
                            inboundTag: Optional[str] = None, secretKey: Optional[str] = None,
                            peers: Optional[List['V2rayConfig.OutboundBean.OutSettingsBean.WireGuardBean']] = None,
                            reserved: Optional[List[int]] = None, mtu: Optional[int] = None, obfsPassword: Optional[str] = None,
                            wnoise:Optional[str]=None,wnoisecount:Optional[str]=None,keepAlive:Optional[int]= None,wnoisedelay:Optional[str]=None,wpayloadsize:Optional[str]=None):
                    self.vnext = vnext
                    self.fragment = fragment
                    self.noises = noises
                    self.servers = servers
                    self.response = response
                    self.network = network
                    self.address = address
                    self.port = port
                    self.domainStrategy = domainStrategy
                    self.redirect = redirect
                    self.userLevel = userLevel
                    self.inboundTag = inboundTag
                    self.secretKey = secretKey
                    self.peers = peers
                    self.reserved = reserved
                    self.mtu = mtu
                    self.obfsPassword = obfsPassword
                    self.wnoise=wnoise
                    self.wnoisecount=wnoisecount
                    self.wnoisedelay=wnoisedelay
                    self.wpayloadsize=wpayloadsize
                    self.keepAlive=keepAlive
                class VnextBean:
                    def __init__(self, address: str = "", port: int = DEFAULT_PORT, users: List['V2rayConfig.OutboundBean.OutSettingsBean.VnextBean.UsersBean'] = None):
                        self.address = address
                        self.port = port
                        self.users = users if users is not None else None
                    class UsersBean:
                        def __init__(self, id: str = "", alterId: Optional[int] = None, security: str = DEFAULT_SECURITY,
                                    level: int = DEFAULT_LEVEL, encryption: str = "", flow: str = ""):
                            self.id = id
                            self.alterId = alterId
                            self.security = security
                            self.level = level
                            self.encryption = encryption
                            self.flow = flow
                class FragmentBean:
                    def __init__(self, packets: Optional[str] = PACKETS, length: Optional[str] = LENGTH, interval: Optional[str] = INTERVAL,host1_domain: Optional[str] = None,host2_domain: Optional[str] = None,):
                        self.packets = packets
                        self.length = length
                        self.interval = interval
                        self.host1_domain = host1_domain
                        self.host2_domain = host2_domain
                class NoiseBean:
                    def __init__(self, type: Optional[str] = None, packet: Optional[str] = None, delay: Optional[str] = None):
                        self.type = type
                        self.packet = packet
                        self.delay = delay
                class ServersBean:
                    def __init__(self, address: str = "", method: Optional[str] = None, ota: bool = False,
                                password: Optional[str] = None, port: int = DEFAULT_PORT, level: int = DEFAULT_LEVEL,
                                email: Optional[str] = None, flow: Optional[str] = None, ivCheck: Optional[bool] = None,
                                users: Optional[List['V2rayConfig.OutboundBean.OutSettingsBean.ServersBean.SocksUsersBean']] = None):
                        self.address = address
                        self.method = method if users is  None else "chacha20-poly1305"
                        self.ota = ota
                        self.password = password
                        self.port = port
                        self.level = level
                        self.email = email
                        self.flow = flow
                        self.ivCheck = ivCheck
                        self.users = users if users is not None else None
                    class SocksUsersBean:
                        def __init__(self, user: str = "", passw: str = "", level: int = DEFAULT_LEVEL):
                            self.user = user
                            self.passw = passw
                            self.level = level
                class Response:
                    def __init__(self, type: str):
                        self.type = type
                class WireGuardBean:
                    def __init__(self, keepAlvie:int=None,publicKey: str = "", endpoint: str = ""):
                        self.publicKey = publicKey
                        self.endpoint = endpoint
                        self.keepAlvie=keepAlvie
            class StreamSettingsBean:
                def __init__(self, network: str = DEFAULT_NETWORK, security: str = "", tcpSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.TcpSettingsBean'] = None,
                            kcpSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.KcpSettingsBean'] = None,
                            wsSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.WsSettingsBean'] = None,
                            httpupgradeSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.HttpupgradeSettingsBean'] = None,
                            xhttpSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.XhttpSettingsBean']= None,
                            splithttpSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.SplithttpSettingsBean'] = None,
                            httpSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.HttpSettingsBean'] = None,
                            tlsSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.TlsSettingsBean'] = None,
                            quicSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.QuicSettingBean'] = None,
                            realitySettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.TlsSettingsBean'] = None,
                            grpcSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.GrpcSettingsBean'] = None,
                            hy2steriaSettings: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.Hy2steriaSettingsBean'] = None,
                            dsSettings: Optional[Any] = None, sockopt: Optional['V2rayConfig.OutboundBean.StreamSettingsBean.SockoptBean'] = None):
                    self.network = network
                    self.security = security
                    self.tcpSettings = tcpSettings
                    self.kcpSettings = kcpSettings
                    self.wsSettings = wsSettings
                    self.httpupgradeSettings = httpupgradeSettings
                    self.splithttpSettings = splithttpSettings
                    self.httpSettings = httpSettings
                    self.tlsSettings = tlsSettings
                    self.quicSettings = quicSettings
                    self.realitySettings = realitySettings
                    self.grpcSettings = grpcSettings
                    self.hy2steriaSettings = hy2steriaSettings
                    self.dsSettings = dsSettings
                    self.sockopt = sockopt
                # ... (Nested classes for TcpSettingsBean, KcpSettingsBean, etc.  -  See below for these) ...
                def populateTransportSettings(self, transport: str, headerType: Optional[str], host: Optional[str], path: Optional[str], seed: Optional[str],
                                            quicSecurity: Optional[str], key: Optional[str], mode: Optional[str], serviceName: Optional[str],
                                            authority: Optional[str]) -> str:
                    sni = ""
                    self.network = transport
                    # ... (Implementation for transport settings - see below)
                    return sni
                def populateTlsSettings(self, streamSecurity: str, allowInsecure: bool, sni: str, fingerprint: Optional[str], alpns: Optional[str],
                                    publicKey: Optional[str], shortId: Optional[str], spiderX: Optional[str]):
                    self.security = streamSecurity
                    # ... (Implementation for TLS settings - see below)
            class MuxBean:
                def __init__(self, enabled: bool, concurrency: int = 8, xudpConcurrency: int = None, xudpProxyUDP443: str = None):
                    self.enabled = enabled
                    self.concurrency = concurrency
                    self.xudpConcurrency = xudpConcurrency
                    self.xudpProxyUDP443 = xudpProxyUDP443
            class HeadersBean:
                def __init__(self, Host: Optional[str] = None, userAgent: Optional[str] = None,
                            acceptEncoding: Optional[str] = None, Connection: Optional[str] = None,
                            Pragma: Optional[str] = None, Host_single: str = ""):  #Added Host_single for WsSettingsBean compatibility
                    self.Host = Host if Host is not None else None
                    self.userAgent = userAgent if userAgent is not None else None
                    self.acceptEncoding = acceptEncoding if acceptEncoding is not None else None
                    self.Connection = Connection if Connection is not None else None
                    self.Pragma = Pragma
                    self.Host_single = Host_single
            class RequestBean:
                def __init__(self, path: List[str] = None, headers:Optional['V2rayConfig.OutboundBean.HeadersBean'] = None, version: Optional[str] = None,
                            method: Optional[str] = None):
                    self.path = path if path is not None else None
                    self.headers = headers if headers is not None else V2rayConfig.OutboundBean.HeadersBean()
                    self.version = version
                    self.method = method
            class HeaderBean:
                def __init__(self, type: str = "none", request:Optional['V2rayConfig.OutboundBean.RequestBean'] = None, response: Any = None):
                    self.type = type
                    self.request = request
                    self.response = response
            class TcpSettingsBean:
                def __init__(self, header: Optional['V2rayConfig.OutboundBean.HeaderBean'] = None, acceptProxyProtocol: Optional[bool] = None):
                    self.header = header if header is not None else V2rayConfig.OutboundBean.HeaderBean()
                    self.acceptProxyProtocol = acceptProxyProtocol
            class KcpSettingsBean:
                def __init__(self, mtu: int = 1350, tti: int = 50, uplinkCapacity: int = 12, downlinkCapacity: int = 100,
                            congestion: bool = False, readBufferSize: int = 1, writeBufferSize: int = 1,
                            header: Optional['V2rayConfig.OutboundBean.HeaderBean'] = None, seed: Optional[str] = None):
                    self.mtu = mtu
                    self.tti = tti
                    self.uplinkCapacity = uplinkCapacity
                    self.downlinkCapacity = downlinkCapacity
                    self.congestion = congestion
                    self.readBufferSize = readBufferSize
                    self.writeBufferSize = writeBufferSize
                    self.header = header if header is not None else V2rayConfig.OutboundBean.HeaderBean(type="none")
                    self.seed = seed
            class WsSettingsBean:
                def __init__(self, path: str = "", headers: Optional['V2rayConfig.OutboundBean.HeadersBean'] = None, maxEarlyData: Optional[int] = None,
                            useBrowserForwarding: Optional[bool] = None, acceptProxyProtocol: Optional[bool] = None,host: Optional[str] = None,):
                    self.path = path
                    self.headers = headers if headers is not None else V2rayConfig.OutboundBean.HeadersBean(Host_single="")
                    self.maxEarlyData = maxEarlyData
                    self.useBrowserForwarding = useBrowserForwarding
                    self.acceptProxyProtocol = acceptProxyProtocol
                    self.host = host
            class HttpupgradeSettingsBean:
                def __init__(self, path: str = "", host: str = "", acceptProxyProtocol: Optional[bool] = None):
                    self.path = path
                    self.host = host
                    self.acceptProxyProtocol = acceptProxyProtocol
            class XhttpSettingsBean:
                def __init__(self,path: Optional[str] = None,host: Optional[str] = None,mode: Optional[str] = None,extra: Optional[Any] = None):
                    self.path = path
                    self.host = host
                    self.mode = mode
            class SplithttpSettingsBean:
                def __init__(self, path: str = "", host: str = "", maxUploadSize: Optional[int] = None,
                            maxConcurrentUploads: Optional[int] = None):
                    self.path = path
                    self.host = host
                    self.maxUploadSize = maxUploadSize
                    self.maxConcurrentUploads = maxConcurrentUploads
            class HttpSettingsBean:
                def __init__(self, host: List[str] = None, path: str = ""):
                    self.host = host if host is not None else None
                    self.path = path
            class SockoptBean:
                def __init__(self, TcpNoDelay: Optional[bool] = None, tcpKeepAliveIdle: Optional[int] = None,
                            tcpFastOpen: Optional[bool] = None, tproxy: Optional[str] = None, mark: Optional[int] = None,
                            dialerProxy: Optional[str] = None):
                    self.TcpNoDelay = TcpNoDelay
                    self.tcpKeepAliveIdle = tcpKeepAliveIdle
                    self.tcpFastOpen = tcpFastOpen
                    self.tproxy = tproxy
                    self.mark = mark
                    self.dialerProxy = dialerProxy
            class TlsSettingsBean:
                def __init__(self, allowInsecure: bool = False, serverName: str = "", alpn: Optional[List[str]] = None,
                            minVersion: Optional[str] = None, maxVersion: Optional[str] = None,
                            preferServerCipherSuites: Optional[bool] = None, cipherSuites: Optional[str] = None,
                            fingerprint: Optional[str] = None, certificates: Optional[List[Any]] = None,
                            disableSystemRoot: Optional[bool] = None, enableSessionResumption: Optional[bool] = None,
                            show: bool = False, publicKey: Optional[str] = None, shortId: Optional[str] = None,
                            spiderX: Optional[str] = None):
                    self.allowInsecure = allowInsecure
                    self.serverName = serverName
                    self.alpn = alpn
                    self.minVersion = minVersion
                    self.maxVersion = maxVersion
                    self.preferServerCipherSuites = preferServerCipherSuites
                    self.cipherSuites = cipherSuites
                    self.fingerprint = fingerprint
                    self.certificates = certificates
                    self.disableSystemRoot = disableSystemRoot
                    self.enableSessionResumption = enableSessionResumption
                    self.show = show
                    self.publicKey = publicKey
                    self.shortId = shortId
                    self.spiderX = spiderX
            class QuicSettingBean:
                def __init__(self, security: str = "none", key: str = "", header: Optional['V2rayConfig.OutboundBean.HeaderBean'] = None):
                    self.security = security
                    self.key = key
                    self.header = header if header is not None else V2rayConfig.OutboundBean.HeaderBean(type="none")
            class GrpcSettingsBean:
                def __init__(self, serviceName: str = "", authority: Optional[str] = None, multiMode: Optional[bool] = None,
                            idle_timeout: Optional[int] = None, health_check_timeout: Optional[int] = None):
                    self.serviceName = serviceName
                    self.authority = authority
                    self.multiMode = multiMode
                    self.idle_timeout = idle_timeout
                    self.health_check_timeout = health_check_timeout
            class Hy2CongestionBean:
                def __init__(self, type: Optional[str] = "bbr", up_mbps: Optional[int] = None, down_mbps: Optional[int] = None):
                    self.type = type
                    self.up_mbps = up_mbps
                    self.down_mbps = down_mbps
            class Hy2steriaSettingsBean:
                def __init__(self, password: Optional[str] = None, use_udp_extension: Optional[bool] = True,
                            congestion: Optional['V2rayConfig.OutboundBean.Hy2CongestionBean'] = None):
                    self.password = password
                    self.use_udp_extension = use_udp_extension
                    self.congestion = congestion
            def split_string_to_list(s: str) -> List[str]:
                return [item.strip() for item in s.split(',') if item.strip()]
            def populate_transport_settings(transport: str, headerType: Optional[str], host: Optional[str], path: Optional[str],
                                            seed: Optional[str], quicSecurity: Optional[str], key: Optional[str],
                                            mode: Optional[str], serviceName: Optional[str], authority: Optional[str]) -> str:
                network = transport
                sni = ""
                if network == "tcp":
                    tcpSetting = V2rayConfig.OutboundBean.TcpSettingsBean()
                    if headerType == HTTP:
                        tcpSetting.header.type = HTTP
                        if host or path:
                            requestObj = V2rayConfig.OutboundBean.RequestBean()
                            requestObj.headers.Host = V2rayConfig.OutboundBean.split_string_to_list(host or "")
                            requestObj.path = V2rayConfig.OutboundBean.split_string_to_list(path or "")
                            tcpSetting.header.request = requestObj
                            sni = requestObj.headers.Host[0] if requestObj.headers.Host else sni
                    else:
                        tcpSetting.header.type = "none"
                        sni = host or ""
                    tcpSettings = tcpSetting # Assuming tcpSettings is a global variable
                elif network == "kcp":
                    kcpsetting = V2rayConfig.OutboundBean.KcpSettingsBean()
                    kcpsetting.header.type = headerType or "none"
                    kcpsetting.seed = seed
                    kcpSettings = kcpsetting
                elif network == "ws":
                    wssetting = V2rayConfig.OutboundBean.WsSettingsBean()
                    wssetting.headers.Host_single = host or ""
                    sni = wssetting.headers.Host_single
                    wssetting.path = path or "/"
                    wsSettings = wssetting
                elif network == "httpupgrade":
                    httpupgradeSetting = V2rayConfig.OutboundBean.HttpupgradeSettingsBean()
                    httpupgradeSetting.host = host or ""
                    sni = httpupgradeSetting.host
                    httpupgradeSetting.path = path or "/"
                    httpupgradeSettings = httpupgradeSetting
                elif network == "xhttp":
                    xhttpSetting = V2rayConfig.OutboundBean.XhttpSettingsBean()
                    xhttpSetting.host = host or ""
                    sni = xhttpSetting.host
                    xhttpSetting.path = path if path else "/"
                    xhttpSettings = xhttpSetting
                elif network == "splithttp":
                    splithttpSetting = V2rayConfig.OutboundBean.SplithttpSettingsBean()
                    splithttpSetting.host = host or ""
                    sni = splithttpSetting.host
                    splithttpSetting.path = path or "/"
                    splithttpSettings = splithttpSetting # Assuming splithttpSettings is a global variable
                elif network in ["h2", "http"]:
                    network = "h2"
                    h2Setting = V2rayConfig.OutboundBean.HttpSettingsBean()
                    h2Setting.host = V2rayConfig.OutboundBean.split_string_to_list(host or "")
                    sni = h2Setting.host[0] if h2Setting.host else sni
                    h2Setting.path = path or "/"
                    httpSettings = h2Setting # Assuming httpSettings is a global variable
                elif network == "quic":
                    quicsetting =V2rayConfig.OutboundBean.QuicSettingBean()
                    quicsetting.security = quicSecurity or "none"
                    quicsetting.key = key or ""
                    quicsetting.header.type = headerType or "none"
                    quicSettings = quicsetting # Assuming quicSettings is a global variable
                elif network == "grpc":
                    grpcSetting = V2rayConfig.OutboundBean.GrpcSettingsBean()
                    grpcSetting.multiMode = mode == False
                    grpcSetting.serviceName = serviceName or ""
                    grpcSetting.authority = authority or ""
                    grpcSetting.idle_timeout = 60
                    grpcSetting.health_check_timeout = 20
                    sni = authority or ""
                    grpcSettings = grpcSetting # Assuming grpcSettings is a global variable
                return sni
            def populate_tls_settings(streamSecurity: str, allowInsecure: bool, sni: str, fingerprint: Optional[str],
                                    alpns: Optional[str], publicKey: Optional[str], shortId: Optional[str],
                                    spiderX: Optional[str]):
                security = streamSecurity
                tlsSetting = V2rayConfig.OutboundBean.TlsSettingsBean(
                    allowInsecure=allowInsecure,
                    serverName=sni,
                    fingerprint=fingerprint,
                    alpn=V2rayConfig.OutboundBean.split_string_to_list(alpns or "") if alpns else None,
                    publicKey=publicKey,
                    shortId=shortId,
                    spiderX=spiderX
                )
                if security == TLS:
                    tlsSettings = tlsSetting
                    realitySettings = None
                elif security == REALITY:
                    tlsSettings = None
                    realitySettings = tlsSetting
        class DnsBean:
            def __init__(self, servers: Optional[List[Any]] = None, hosts: Optional[Dict[str, Any]] = None,
                        clientIp: Optional[str] = None, disableCache: Optional[bool] = None,
                        queryStrategy: Optional[str] = None, tag: Optional[str] = None,fakedns:Optional[list]=None):
                self.servers = servers
                self.hosts = hosts
                self.fakedns = fakedns
                self.clientIp = clientIp
                self.disableCache = disableCache
                self.queryStrategy = queryStrategy
                self.tag = tag
            class ServersBean:
                def __init__(self, address: str = "", port: Optional[int] = None, domains: Optional[List[str]] = None,
                            expectIPs: Optional[List[str]] = None, clientIp: Optional[str] = None):
                    self.address = address
                    self.port = port
                    self.domains = domains
                    self.expectIPs = expectIPs
                    self.clientIp = clientIp
        class RoutingBean:
            def __init__(self, domainStrategy: str, domainMatcher: Optional[str] = None,
                        rules: List['V2rayConfig.RoutingBean.RulesBean'] = None, balancers: Optional[List[Any]] = None):
                self.domainStrategy = domainStrategy
                self.domainMatcher = domainMatcher
                self.rules = rules if rules is not None else None
                self.balancers = balancers
            class RulesBean:
                def __init__(self, type: str = "field", ip: Optional[List[str]] = None, domain: Optional[List[str]] = None,
                            outboundTag: str = "", balancerTag: Optional[str] = None, port: Optional[str] = None,
                            sourcePort: Optional[str] = None, network: Optional[str] = None, source: Optional[List[str]] = None,
                            user: Optional[List[str]] = None, inboundTag: Optional[List[str]] = None,
                            protocol: Optional[List[str]] = None, attrs: Optional[str] = None, domainMatcher: Optional[str] = None, enabled: Optional[bool]=None,id:Optional[str]=None):
                    self.type = type
                    self.ip = ip
                    self.id=id
                    self.domain = domain
                    self.outboundTag = outboundTag
                    self.balancerTag = balancerTag
                    self.port = port
                    self.sourcePort = sourcePort
                    self.network = network
                    self.source = source
                    self.user = user
                    self.inboundTag = inboundTag
                    self.protocol = protocol
                    self.attrs = attrs
                    self.domainMatcher = domainMatcher
                    self.enabled=enabled
        class PolicyBean:
            def __init__(self, levels: Dict[str, 'V2rayConfig.PolicyBean.LevelBean'], system: Optional[Any] = None):
                self.levels = levels
                self.system = system
            class LevelBean:
                def __init__(self, handshake: Optional[int] = None, connIdle: Optional[int] = None,
                            uplinkOnly: Optional[int] = None, downlinkOnly: Optional[int] = None,
                            statsUserUplink: Optional[bool] = None, statsUserDownlink: Optional[bool] = None,
                            bufferSize: Optional[int] = None):
                    self.handshake = handshake
                    self.connIdle = connIdle
                    self.uplinkOnly = uplinkOnly
                    self.downlinkOnly = downlinkOnly
                    self.statsUserUplink = statsUserUplink
                    self.statsUserDownlink = statsUserDownlink
                    self.bufferSize = bufferSize
        class FakednsBean:
            def __init__(self, ipPool: str = "198.18.0.0/15", poolSize: int = 10000):
                self.ipPool = ipPool
                self.poolSize = poolSize
        outbounds = []
        class EConfigType:
            entries = []
        def getProxyOutbound():
            for outbound in V2rayConfig.outbounds:
                for it in V2rayConfig.EConfigType.entries:
                    if outbound.protocol.lower() == it.name.lower():
                        return outbound
        def to_dict(self):
            result = {}
            for key, value in self.__dict__.items():
                if value is not None:
                    if isinstance(value, list):
                        result[key] = [item.to_dict() if hasattr(item, 'to_dict') else item for item in value if item is not None]
                    elif hasattr(value, 'to_dict'):
                        result[key] = value.to_dict()
                    else:
                        result[key] = value
            return result
        def toPrettyPrinting(self) -> str:
            return json.dumps(self.to_dict(), indent=4, cls=MyEncoder)
        def __str__(self):
            return self.toPrettyPrinting()
    class MyEncoder(JSONEncoder):
        def default(self, o):
            if hasattr(o, 'to_dict'):
                return o.to_dict()
            return o.__dict__
    class V2rayConfigLogBean:
        def __init__(self, access: str, error: str, loglevel: Optional[str] = None, dnsLog: Optional[bool] = None):
            self.access = access
            self.error = error
            self.loglevel = loglevel
            self.dnsLog = dnsLog
        def to_dict(self):
            result = {}
            for key, value in self.__dict__.items():
                if value is not None:
                    result[key] = value
            return result
    def remove_nulls(data):
        if isinstance(data, dict):
            return {k: remove_nulls(v) for k, v in data.items() if v is not None}
        elif isinstance(data, list):
            return [remove_nulls(item) for item in data if item is not None]
        elif hasattr(data, '__dict__'):
            obj_dict = data.__dict__
            cleaned_dict = {k: remove_nulls(v) for k, v in obj_dict.items() if v is not None}
            return cleaned_dict
        else:
            return data
    def replace_accept_encoding(d):
        if isinstance(d, dict):
            new_dict = {}
            for key, value in d.items():
                if key == 'acceptEncoding':
                    new_dict['Accept-Encoding'] = value
                elif key == 'passw':
                    new_dict['pass'] = value
                else:
                    new_dict[key] = replace_accept_encoding(value)
            return new_dict
        elif isinstance(d, list):
            return [replace_accept_encoding(item) for item in d]
        elif hasattr(d, '__dict__'):
                obj_dict = d.__dict__
                cleaned_dict = {itemk: replace_accept_encoding(itemk) for itemk,itemv in obj_dict.items()}
                return cleaned_dict
        else:
            return d
    ID,ADDRESS,PORT,SECURITY,ALPN,FP,SNI,SPX,HEADER_TYPE,ENCRYPTION,TYPE,MODE,FLOW,ALTERID,R_HOST,PATH,SCY,PASS,SID,METHOD,OBFS_PASSWORD,INSECURE,PORTHOPINGINTERVAL,PINSHA256,OBFS,USER,WNOISE,WNOISECOUNT,WNOISEDELAY,WPAYLOADSIZE,KEEPALIVE,MTU,ENDPOINT,RESERVED,PBK,SECERKEY,REMARKS,protocol_c=(dict_conf.id, dict_conf.address,dict_conf.port,dict_conf.security,dict_conf.alpn,dict_conf.fp,dict_conf.sni,dict_conf.spx,dict_conf.header_type,dict_conf.encryption,dict_conf.type,dict_conf.mode,dict_conf.flow,dict_conf.alter_id,dict_conf.host,dict_conf.path,dict_conf.scy,dict_conf.ss_password,dict_conf.sid,dict_conf.ss_method,dict_conf.hy2_obfs_password,dict_conf.hy2_insecure,dict_conf.hy2_hop_interval,dict_conf.hy2_pinsha256,dict_conf.hy2_obfs,dict_conf.socks_user,dict_conf.wnoise,dict_conf.wnoisecount,dict_conf.wnoisedelay,dict_conf.wpayloadsize,dict_conf.wg_keep_alive,dict_conf.wg_mtu,dict_conf.address,dict_conf.wg_reserved,dict_conf.pbk,dict_conf.wg_secret_key,dict_conf.tag,dict_conf.protocol)
    if SECURITY=="none":
            SECURITY=""
    if INSECURE=="0": INSECURE=False
    else: INSECURE=True
    if RESERVED!="":
        RESERVED = list(map(int, RESERVED.split(",")))
    if MODE=="gun" and TYPE=="grpc":
        MODE=False
    elif MODE=="multi" and TYPE=="grpc":
        MODE=True
    if protocol_c=="wireguard":
        ADDRESS=dict_conf.wg_address.split(",")
        PBK=dict_conf.wg_public_key
    if IS_WARP_ON_WARP:
        warp_conf=parse_configs_by_get(WARPONWARP)
        WNOISEON,WNOISECOUNTON,WNOISEDELAYON,WPAYLOADSIZEON,KEEPALIVEON,MTUON,SECERKEYON,ENDPOINTON,PORTON,ADDRESSON,RESERVEDON,PBKON=(warp_conf.wnoise,warp_conf.wnoisecount,warp_conf.wnoisedelay,warp_conf.wpayloadsize,warp_conf.wg_keep_alive,warp_conf.wg_mtu,warp_conf.wg_secret_key,warp_conf.address,warp_conf.port,warp_conf.wg_address.split(","),warp_conf.wg_reserved,warp_conf.wg_public_key)
        if RESERVEDON!="":
            RESERVEDON = list(map(int, RESERVEDON.split(",")))
    ##################################################################################################
    def parse_yaml_hy2():
        yaml_hy2={
            'server':ADDRESS+":"+str(PORT),
            'auth':PASS,
            'transport':{
                'type':'udp',
                'udp':{
                    'hopInterval':str(PORTHOPINGINTERVAL)+'s'
            },
            }
        }
        if SECURITY=="tls":
            tlsin={'tls':{
                'insecure':INSECURE
            }
            }
            if SNI!="":
                tlsin.update({'sni':SNI})
            if PINSHA256!="":
                tlsin.update({'pinSHA256':PINSHA256})
            yaml_hy2.update(tlsin)
        if OBFS=="salamander":
            obfsin={
                'obfs':{
                    'type':'salamander',
                    'salamander':{
                        'password':OBFS_PASSWORD
                    }
                }
            }
            yaml_hy2.update(obfsin)
        nest_yaml_hy2={
            'bandwidth':{
                'up':'20 mbps',
                'down':'100 mbps'
            },
            'quic':{
                'initStreamReceiveWindow': 8388608,
                'maxStreamReceiveWindow': 8388608,
                'initConnReceiveWindow': 20971520,
                'maxConnReceiveWindow': 20971520,
                'maxIdleTimeout': '30s',
                'keepAlivePeriod': '10s',
                'disablePathMTUDiscovery': False
            },
            'fastOpen':True,
            'lazy':True,
            'socks5':{
                'listen':LOCAL_HOST+':'+str(SOCKS5+2),
            },
            'http':{
                'listen':LOCAL_HOST+':'+str(HTTP5+2)
            }
        }
        yaml_hy2.update(nest_yaml_hy2)
        return yaml_hy2
    if conifg.startswith("hy2://") or conifg.startswith("hysteria2://"):
        with open(hy2_path,'w') as f:
            yaml.dump(parse_yaml_hy2(),f)
        return parse_configs(conifg=f"socks://Og==@{LOCAL_HOST}:{str(SOCKS5+2)}#hy2",cv=cv,is_hy2=True)
    try:
            ALPN=ALPN.split(",")
    except Exception:
            pass
    logBean = V2rayConfigLogBean("", "",LOGLEVEL)  # Make sure to adjust the imports for these
    inboundBean = V2rayConfig.InboundBean(tag="socks", port=SOCKS5, protocol="socks",listen=LOCAL_HOST, sniffing=V2rayConfig.InboundBean.SniffingBean(False, [],routeOnly=False),settings=V2rayConfig.InboundBean.InSettingsBean(auth="noauth",udp=True,allowTransparent=False))
    inboundBean2=V2rayConfig.InboundBean(tag="http", listen=LOCAL_HOST,port=HTTP5, protocol="http",settings=V2rayConfig.InboundBean.InSettingsBean(userLevel=8))
    sniff_list=[]
    sniff_enable=False
    if SNIFFING:
        sniff_list+=["http","tls"]
        sniff_enable=True
    if ENABLELOCALDNS:
        if ENABLEFAKEDNS:
            inboundBean = V2rayConfig.InboundBean(tag="socks", port=SOCKS5, protocol="socks",listen=LOCAL_HOST, sniffing=V2rayConfig.InboundBean.SniffingBean(True, sniff_list+["fakedns"],routeOnly=False),settings=V2rayConfig.InboundBean.InSettingsBean(auth="noauth",udp=True,allowTransparent=False))
            inboundBean3=V2rayConfig.InboundBean(listen=LOCAL_HOST,port=LOCALDNSPORT,protocol="dokodemo-door",settings=V2rayConfig.InboundBean.InSettingsBean(address="8.8.8.8", network="tcp,udp", port=53), tag="dns-in")
        else:
            inboundBean = V2rayConfig.InboundBean(tag="socks", port=SOCKS5, protocol="socks",listen=LOCAL_HOST, sniffing=V2rayConfig.InboundBean.SniffingBean(sniff_enable,sniff_list,routeOnly=False),settings=V2rayConfig.InboundBean.InSettingsBean(auth="noauth",udp=True,allowTransparent=False))
            inboundBean3=V2rayConfig.InboundBean(listen=LOCAL_HOST,port=LOCALDNSPORT,protocol="dokodemo-door",settings=V2rayConfig.InboundBean.InSettingsBean(address="8.8.8.8", network="tcp,udp", port=53), tag="dns-in")
    outboundBean=""
    if IS_WARP_ON_WARP:
        outboundBeanwow = V2rayConfig.OutboundBean(tag="warp-out", protocol="wireguard",settings=V2rayConfig.OutboundBean.OutSettingsBean(address=ADDRESSON, mtu=MTUON,reserved=RESERVEDON,secretKey=SECERKEYON,wnoise=WNOISEON,wnoisecount=WNOISECOUNTON,wnoisedelay=WNOISEDELAYON,wpayloadsize=WPAYLOADSIZEON,keepAlive=KEEPALIVEON,peers=[V2rayConfig.OutboundBean.OutSettingsBean.WireGuardBean(endpoint=ENDPOINTON+":"+str(PORTON) ,publicKey=PBKON)]),streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="",sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="proxy")))
    rulesBean=[]
    domainrule=[]
    iprule=[]
    domaindirectdns=[]
    hostdomains={"domain:googleapis.cn":"googleapis.com"}
    if CUSTOMRULES_PROXY[0]!="":
        for i in CUSTOMRULES_PROXY:
            found_num=any(ch.isdigit() for ch in i)
            if not found_num and not "geoip" in i:
                domainrule.append(i)
            else:
                iprule.append(i)
        if domainrule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",domain=domainrule,outboundTag="proxy",enabled=True))
        if iprule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",ip=iprule,outboundTag="proxy",enabled=True))
        domainrule=[]
        iprule=[]
    if CUSTOMRULES_DIRECT[0]!="":
        for i in CUSTOMRULES_DIRECT:
            found_num=any(ch.isdigit() for ch in i)
            if not found_num and not "geoip" in i:
                domainrule.append(i)
            else:
                iprule.append(i)
            domaindirectdns.extend(domainrule)
        if domainrule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",domain=domainrule,outboundTag="direct",enabled=True))
        if iprule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",ip=iprule,outboundTag="direct",enabled=True))
        domainrule=[]
        iprule=[]
    if CUSTOMRULES_BLOCKED[0]!="":
        for i in CUSTOMRULES_BLOCKED:
            found_num=any(ch.isdigit() for ch in i)
            if not found_num and not "geoip" in i:
                domainrule.append(i)
            else:
                iprule.append(i)
            if "geosite" in i or  "domain" in i:
                hostdomains.update({f"{i}":LOCAL_HOST})
        if domainrule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",domain=domainrule,outboundTag="block",enabled=True))
        if iprule!=[]:
            rulesBean.append(V2rayConfig.RoutingBean.RulesBean(type="field",ip=iprule,outboundTag="block",enabled=True))
    hostdomains.update({
    "dns.pub": [
    "1.12.12.12",
    "120.53.53.53"
    ],
    "dns.alidns.com": [
    "223.5.5.5",
    "223.6.6.6",
    "2400:3200::1",
    "2400:3200:baba::1"
    ],
    "one.one.one.one": [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001"
    ],
    "dns.google": [
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844"
    ]})
    routingBean=V2rayConfig.RoutingBean(domainStrategy=DOMAINSTRATEGY,rules=rulesBean)
    ######servers
    if not ENABLELOCALDNS:
        dnsBeanSERVERS=[REMOTEDNS]
    else:
        if not ENABLEFAKEDNS:
            dnsBeanSERVERS=[V2rayConfig.DnsBean.ServersBean(address=DOMESTICDNS,domains=["geosite:cn"]+domaindirectdns,expectIPs=["geoip:cn"],port=53),REMOTEDNS]
        else:
            dnsBeanSERVERS=[V2rayConfig.DnsBean.ServersBean(address=DOMESTICDNS,domains=["geosite:cn"]+domaindirectdns,expectIPs=["geoip:cn"],port=53),V2rayConfig.DnsBean.ServersBean(address="fakedns",domains=["geosite:cn"]+domaindirectdns),REMOTEDNS]
    dnsBean=V2rayConfig.DnsBean(hosts=hostdomains,servers=dnsBeanSERVERS,fakedns=V2rayConfig.FakednsBean(ipPool="198.18.0.0/15",poolSize=10000))
    def check_type():
        header=V2rayConfig.OutboundBean.HeaderBean()
        if HEADER_TYPE=="http" and TYPE=="tcp":
            headers=V2rayConfig.OutboundBean.HeadersBean(Connection=["keep-alive"], Host=[R_HOST],Pragma="no-cache",acceptEncoding=["gzip, deflate"],userAgent=["Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"])
            requests=V2rayConfig.OutboundBean.RequestBean(headers=headers,method="GET",path=PATH,version="1.1")
            header=V2rayConfig.OutboundBean.HeaderBean(type="http",request=requests)
        outboundBean_Stream_tcpsettings=V2rayConfig.OutboundBean.TcpSettingsBean(header=header)
        if TYPE=="kcp":
            outboundBean_Stream_kcp_settings=V2rayConfig.OutboundBean.KcpSettingsBean(congestion=False,downlinkCapacity=100,header=V2rayConfig.OutboundBean.HeaderBean(type=HEADER_TYPE),mtu=1350,readBufferSize=1,seed=PATH,tti=50,uplinkCapacity=12,writeBufferSize=1)
        elif TYPE=="ws":
            if R_HOST:
                ws_headers = V2rayConfig.OutboundBean.HeadersBean(Host=R_HOST)
            else:
                ws_headers=None
            outboundBean_Stream_ws_settings=V2rayConfig.OutboundBean.WsSettingsBean(headers=ws_headers,path=PATH)
        elif TYPE=="httpupgrade":
            outboundBean_Stream_httpupgrade_settings=V2rayConfig.OutboundBean.HttpupgradeSettingsBean(host=R_HOST,path=PATH)
        elif TYPE=="xhttp":
            outboundBean_Stream_xhttp_settings=V2rayConfig.OutboundBean.XhttpSettingsBean(host=R_HOST,path=PATH,mode=MODE,)
        elif TYPE=="splithttp":
            outboundBean_Stream_splithttp_settings=V2rayConfig.OutboundBean.SplithttpSettingsBean(host=R_HOST,path=PATH)
        elif TYPE=="h2":
            outboundBean_Stream_h2_settings=V2rayConfig.OutboundBean.HttpSettingsBean(host=[R_HOST],path=PATH)
        elif TYPE=="quic":
            outboundBean_Stream_quic_settings=V2rayConfig.OutboundBean.QuicSettingBean(header=V2rayConfig.OutboundBean.HeaderBean(type=HEADER_TYPE),key=PATH,security=R_HOST)
        elif TYPE=="grpc":
            outboundBean_Stream_grpc_settings=V2rayConfig.OutboundBean.GrpcSettingsBean(authority=R_HOST,serviceName=PATH,multiMode=MODE,)
        if SECURITY!="reality":
            outboundBean_Stream_tlssettings=V2rayConfig.OutboundBean.TlsSettingsBean(allowInsecure=ALLOWINCREASE,alpn=ALPN,fingerprint=FP,serverName=SNI,show=False)
        else:
            outboundBean_Stream_tlssettings=V2rayConfig.OutboundBean.TlsSettingsBean(allowInsecure=ALLOWINCREASE,alpn=ALPN,fingerprint=FP,publicKey=PBK,serverName=SNI,shortId=SID,spiderX=SPX,show=False)
        if FRAGMENT:
            if  SECURITY=="reality" :
                if TYPE=="tcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security=SECURITY,tcpSettings=outboundBean_Stream_tcpsettings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="kcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="kcp",security=SECURITY,kcpSettings=outboundBean_Stream_kcp_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="ws":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="ws",security=SECURITY,wsSettings=outboundBean_Stream_ws_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="httpupgrade":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpupgrade",security=SECURITY,httpupgradeSettings=outboundBean_Stream_httpupgrade_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="xhttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpx",security=SECURITY,xhttpSettings=outboundBean_Stream_xhttp_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="splithttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="splithttp",security=SECURITY,splithttpSettings=outboundBean_Stream_splithttp_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="h2":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="h2",security=SECURITY,httpSettings=outboundBean_Stream_h2_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="quic":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="quic",security=SECURITY,quicSettings=outboundBean_Stream_quic_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="grpc":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="grpc",security=SECURITY,grpcSettings=outboundBean_Stream_grpc_settings,realitySettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
            else:
                if TYPE=="tcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security=SECURITY,tcpSettings=outboundBean_Stream_tcpsettings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="kcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="kcp",security=SECURITY,kcpSettings=outboundBean_Stream_kcp_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="ws":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="ws",security=SECURITY,wsSettings=outboundBean_Stream_ws_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="httpupgrade":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpupgrade",security=SECURITY,httpupgradeSettings=outboundBean_Stream_httpupgrade_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="xhttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpx",security=SECURITY,xhttpSettings=outboundBean_Stream_xhttp_settings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="splithttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="splithttp",security=SECURITY,splithttpSettings=outboundBean_Stream_splithttp_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="h2":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="h2",security=SECURITY,httpSettings=outboundBean_Stream_h2_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="quic":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="quic",security=SECURITY,quicSettings=outboundBean_Stream_quic_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
                elif TYPE=="grpc":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="grpc",security=SECURITY,grpcSettings=outboundBean_Stream_grpc_settings,tlsSettings=outboundBean_Stream_tlssettings,sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255))
        else:
            if  SECURITY=="reality" :
                if TYPE=="tcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security=SECURITY,tcpSettings=outboundBean_Stream_tcpsettings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="kcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="kcp",security=SECURITY,kcpSettings=outboundBean_Stream_kcp_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="ws":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="ws",security=SECURITY,wsSettings=outboundBean_Stream_ws_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="httpupgrade":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpupgrade",security=SECURITY,httpupgradeSettings=outboundBean_Stream_httpupgrade_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="xhttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpx",security=SECURITY,xhttpSettings=outboundBean_Stream_xhttp_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="splithttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="splithttp",security=SECURITY,splithttpSettings=outboundBean_Stream_splithttp_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="h2":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="h2",security=SECURITY,httpSettings=outboundBean_Stream_h2_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="quic":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="quic",security=SECURITY,quicSettings=outboundBean_Stream_quic_settings,realitySettings=outboundBean_Stream_tlssettings)
                elif TYPE=="grpc":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="grpc",security=SECURITY,grpcSettings=outboundBean_Stream_grpc_settings,realitySettings=outboundBean_Stream_tlssettings)
            else:
                if TYPE=="tcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security=SECURITY,tcpSettings=outboundBean_Stream_tcpsettings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="kcp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="kcp",security=SECURITY,kcpSettings=outboundBean_Stream_kcp_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="ws":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="ws",security=SECURITY,wsSettings=outboundBean_Stream_ws_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="httpupgrade":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpupgrade",security=SECURITY,httpupgradeSettings=outboundBean_Stream_httpupgrade_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="xhttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="httpx",security=SECURITY,xhttpSettings=outboundBean_Stream_xhttp_settings)
                elif TYPE=="splithttp":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="splithttp",security=SECURITY,splithttpSettings=outboundBean_Stream_splithttp_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="h2":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="h2",security=SECURITY,httpSettings=outboundBean_Stream_h2_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="quic":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="quic",security=SECURITY,quicSettings=outboundBean_Stream_quic_settings,tlsSettings=outboundBean_Stream_tlssettings)
                elif TYPE=="grpc":
                    outboundBean_Stream_tcp=V2rayConfig.OutboundBean.StreamSettingsBean(network="grpc",security=SECURITY,grpcSettings=outboundBean_Stream_grpc_settings,tlsSettings=outboundBean_Stream_tlssettings)
        return outboundBean_Stream_tcp
    if conifg.startswith("vless://"):
        outboundBean_Stream_tcp=check_type()
        outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="vless", settings=V2rayConfig.OutboundBean.OutSettingsBean(vnext=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean (address=ADDRESS, port=PORT, users=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean.UsersBean(id=ID,security="auto",level=8,encryption=ENCRYPTION,flow=FLOW,alterId=0)])]),mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),streamSettings=outboundBean_Stream_tcp)
    elif conifg.startswith("vmess://"):
        outboundBean_Stream_tcp=check_type()
        outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="vmess", settings=V2rayConfig.OutboundBean.OutSettingsBean(vnext=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean (address=ADDRESS, port=PORT, users=[V2rayConfig.OutboundBean.OutSettingsBean.VnextBean.UsersBean(id=ID,security=SCY,level=8,encryption="",flow="",alterId=ALTERID)])]),mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),streamSettings=outboundBean_Stream_tcp)
    elif conifg.startswith("trojan://"):
        outboundBean_Stream_tcp=check_type()
        outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="trojan" ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),streamSettings=outboundBean_Stream_tcp,settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS, port=PORT,method= "chacha20-poly1305", ota=False,level=8,password=PASS)] ))
    elif conifg.startswith("ss://"):
        sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255)
        if FRAGMENT:
            outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="shadowsocks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="",sockopt=sockopt) ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS,method=METHOD, port=PORT, ota=False,level=8,password=PASS)] ))
        else:
            outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="shadowsocks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="") ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean ( address=ADDRESS, port=PORT,method=METHOD, ota=False,level=8,password=PASS)] ))
    elif conifg.startswith("socks://"):
        if is_hy2:
            FRAGMENT=False
            IS_WARP_ON_WARP=False
            MUX_ENABLE=False
        print(FRAGMENT, is_hy2)
        sockopt=V2rayConfig.OutboundBean.SockoptBean(dialerProxy="fragment",tcpKeepAliveIdle=100,mark=255)
        if FRAGMENT==False:
            if PASS=="" and USER=="":
                outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="socks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="") ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS,method=METHOD, port=PORT, ota=False,level=8,password="")] ))
            else:
                outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="socks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="") ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS,method=METHOD, port=PORT, ota=False,level=8,password="",users=V2rayConfig.OutboundBean.OutSettingsBean.ServersBean.SocksUsersBean(level=8,passw=PASS,user=USER))] ))
        else:
            if PASS=="" and USER=="":
                outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="socks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="",sockopt=sockopt) ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS,method=METHOD, port=PORT, ota=False,level=8,password="")] ))
            else:
                outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="socks",streamSettings=V2rayConfig.OutboundBean.StreamSettingsBean(network="tcp",security="",sockopt=sockopt) ,mux=V2rayConfig.OutboundBean.MuxBean(enabled=MUX_ENABLE,concurrency=CONCURRENCY,xudpConcurrency=CONCURRENCY,xudpProxyUDP443=""),settings=V2rayConfig.OutboundBean.OutSettingsBean(servers=[V2rayConfig.OutboundBean.OutSettingsBean.ServersBean (address=ADDRESS,method=METHOD, port=PORT, ota=False,level=8,password="",users=V2rayConfig.OutboundBean.OutSettingsBean.ServersBean.SocksUsersBean(level=8,passw=PASS,user=USER))] ))
    elif conifg.startswith("wireguard://"):
        FRAGMENT=False
        is_warp=True
        outboundBean = V2rayConfig.OutboundBean(tag="proxy", protocol="wireguard",settings=V2rayConfig.OutboundBean.OutSettingsBean(address=ADDRESS, mtu=MTU,reserved=RESERVED,secretKey=SECERKEY,wnoise=WNOISE,wnoisecount=WNOISECOUNT,wnoisedelay=WNOISEDELAY,wpayloadsize=WPAYLOADSIZE,keepAlive=KEEPALIVE,peers=[V2rayConfig.OutboundBean.OutSettingsBean.WireGuardBean(endpoint=ENDPOINT+":"+str(PORT) ,publicKey=PBK)]))
    end_outbound_bf_frg_set=V2rayConfig.OutboundBean.BeforeFrgSettings(tag="direct",protocol="freedom",settings={})
    end_outbound_bf_frg_set2=V2rayConfig.OutboundBean.BeforeFrgSettings(tag="block",protocol="blackhole",settings={"response":{"type":"http"}})
    if FRAGMENT:
        if FAKEHOST_ENABLE:
            frg=V2rayConfig.OutboundBean.OutSettingsBean.FragmentBean(packets=PACKETS,length=LENGTH,interval=INTERVAL,host1_domain=HOST1_DOMAIN,host2_domain=HOST2_DOMAIN)
        else:
            frg=V2rayConfig.OutboundBean.OutSettingsBean.FragmentBean(packets=PACKETS,length=LENGTH,interval=INTERVAL)
        frg_stream=V2rayConfig.OutboundBean.StreamSettingsBean(network=None,security=None,sockopt=V2rayConfig.OutboundBean.SockoptBean(TcpNoDelay=True,tcpKeepAliveIdle=100,mark=255))
        bf_frg_set=V2rayConfig.OutboundBean.BeforeFrgSettings(tag="fragment",protocol="freedom",settings=frg,streamSettings=frg_stream)
        if ENABLELOCALDNS:
            config = V2rayConfig(log=logBean,dns=dnsBean,  inbounds=[inboundBean,inboundBean2,inboundBean3], outbounds=[outboundBean,bf_frg_set,end_outbound_bf_frg_set,end_outbound_bf_frg_set2],remarks=REMARKS,routing=routingBean)
        else:
            config = V2rayConfig(log=logBean,dns=dnsBean,  inbounds=[inboundBean,inboundBean2], outbounds=[outboundBean,bf_frg_set,end_outbound_bf_frg_set,end_outbound_bf_frg_set2],remarks=REMARKS,routing=routingBean)
    else:
        if is_warp==False:
            if IS_WARP_ON_WARP:
                if ENABLELOCALDNS:
                    config = V2rayConfig(log=logBean,dns=dnsBean, inbounds=[inboundBean,inboundBean2,inboundBean3], outbounds=[outboundBeanwow,outboundBean,end_outbound_bf_frg_set,end_outbound_bf_frg_set2],remarks=REMARKS,routing=routingBean)
                else:
                    config = V2rayConfig(log=logBean,dns=dnsBean, inbounds=[inboundBean,inboundBean2], outbounds=[outboundBeanwow,outboundBean,end_outbound_bf_frg_set,end_outbound_bf_frg_set2],remarks=REMARKS,routing=routingBean)
            else:
                config = V2rayConfig(log=logBean,dns=dnsBean, inbounds=[inboundBean,inboundBean2], outbounds=[outboundBean,end_outbound_bf_frg_set,end_outbound_bf_frg_set2],remarks=REMARKS,routing=routingBean)
        else:
            bf_after_warp_set=V2rayConfig.OutboundBean.BeforeFrgSettings(protocol="freedom",settings={"domainStrategy": "UseIP"},tag="direct")
            after_warp_set=V2rayConfig.OutboundBean.BeforeFrgSettings(protocol="blackhole",settings={"response":{"type": "http"}},tag="block")
            after_warp_set2=V2rayConfig.OutboundBean.BeforeFrgSettings(protocol="dns",tag="dns-out")
            if IS_WARP_ON_WARP:
                if ENABLELOCALDNS:
                    config = V2rayConfig(log=logBean,stats={},dns=dnsBean, inbounds=[inboundBean,inboundBean2,inboundBean3], outbounds=[outboundBeanwow,outboundBean,bf_after_warp_set,after_warp_set,after_warp_set2],remarks=REMARKS,routing=routingBean)
                else:
                    config = V2rayConfig(log=logBean,stats={},dns=dnsBean, inbounds=[inboundBean,inboundBean2], outbounds=[outboundBeanwow,outboundBean,bf_after_warp_set,after_warp_set,after_warp_set2],remarks=REMARKS,routing=routingBean)
            else:
                if ENABLELOCALDNS:
                    config = V2rayConfig(log=logBean,stats={},dns=dnsBean, inbounds=[inboundBean,inboundBean2,inboundBean3], outbounds=[outboundBean,bf_after_warp_set,after_warp_set,after_warp_set2],remarks=REMARKS,routing=routingBean)
                else:
                    config = V2rayConfig(log=logBean,stats={},dns=dnsBean, inbounds=[inboundBean,inboundBean2], outbounds=[outboundBean,bf_after_warp_set,after_warp_set,after_warp_set2],remarks=REMARKS,routing=routingBean)
    data_conf=remove_nulls(config)
    data_conf=replace_accept_encoding(data_conf)
    data_conf=json.dumps(data_conf, indent=4, cls=MyEncoder)
    return data_conf
def is_ip_accessible_from_iran_via_check_host(ip_to_check_on_checkhost: str,
                                               proxies_to_use: Optional[dict],
                                               timeout_seconds: int = 35) -> Optional[bool]:
    """
    Checks if an IP address (ip_to_check_on_checkhost) is pingable from Iran using check-host.net,
    with the request to check-host.net itself going through proxies_to_use.
    Returns:
        False: If ip_to_check_on_checkhost is accessible from Iran (confirmed by check-host).
        True: If ip_to_check_on_checkhost is inaccessible from Iran (confirmed by check-host).
        None: If check-host.net service had an issue (rate limit, error, inconclusive) when accessed via proxies_to_use.
    """
    if not ip_to_check_on_checkhost:
        print(f"CHECK-HOST (via proxy): No target IP provided to check on check-host.net.")
        return True
    proxy_display = proxies_to_use.get('http', 'None') if proxies_to_use else 'None'
    print(f"CHECK-HOST (via proxy {proxy_display}): Checking Iran PING for target IP {ip_to_check_on_checkhost}")
    check_host_api_url_base = "https://check-host.net/check-ping"
    headers = {"Accept": "application/json", "User-Agent": "MyConfigTester/1.2"}
    accessible_from_at_least_one_node = False
    any_node_test_completed_without_service_error = False
    for node_idx, node in enumerate(CHECK_HOST_IRANIAN_NODES):
        if accessible_from_at_least_one_node:
            break
        try:
            init_url = f"{check_host_api_url_base}?host={ip_to_check_on_checkhost}&node={node}&max_nodes=1"
            response_init = requests.get(init_url, headers=headers, timeout=10, proxies=proxies_to_use)
            if response_init.status_code == 429:
                print(f"  CH_PROXY: Rate limited by check-host.net for {ip_to_check_on_checkhost} (node {node}) when using proxy {proxy_display}.")
                return None
            response_init.raise_for_status()
            init_data = response_init.json()
            if init_data.get("ok") != 1:
                error_msg = init_data.get('error', 'Unknown error during PING check initiation')
                print(f"  CH_PROXY: PING init API error for {ip_to_check_on_checkhost} (node {node}) (proxy {proxy_display}): {error_msg}")
                if "limit for your ip" in error_msg.lower() or "many requests" in error_msg.lower():
                    return None
                any_node_test_completed_without_service_error = True
                continue
            request_id = init_data.get("request_id")
            if not request_id:
                print(f"  CH_PROXY: No request_id for {ip_to_check_on_checkhost} (node {node}) (proxy {proxy_display}).")
                any_node_test_completed_without_service_error = True
                continue
            result_url = f"https://check-host.net/check-result/{request_id}"
            polling_deadline = time.time() + (timeout_seconds - 10)
            node_ping_to_target_successful = False
            while time.time() < polling_deadline:
                time.sleep(3)
                try:
                    response_result = requests.get(result_url, headers=headers, timeout=5, proxies=proxies_to_use)
                    if response_result.status_code == 429:
                        print(f"  CH_PROXY: Rate limited during polling for {request_id} (node {node}) (proxy {proxy_display}).")
                        return None
                    response_result.raise_for_status()
                    result_data_for_all_nodes_in_req = response_result.json()
                    if not result_data_for_all_nodes_in_req: continue
                    node_specific_result_list = result_data_for_all_nodes_in_req.get(node)
                    if node_specific_result_list:
                        any_node_test_completed_without_service_error = True
                        if isinstance(node_specific_result_list, list) and len(node_specific_result_list) > 0:
                            first_attempt_group = node_specific_result_list[0]
                            if first_attempt_group and isinstance(first_attempt_group, list) and len(first_attempt_group) > 0:
                                ping_stats = first_attempt_group[0]
                                if ping_stats and isinstance(ping_stats, list) and len(ping_stats) >= 4:
                                    avg_rtt_val_str = ping_stats[3]
                                    if avg_rtt_val_str is not None and "ms" in avg_rtt_val_str:
                                        print(f"  CH_PROXY: Target IP {ip_to_check_on_checkhost} ACCESSIBLE from Iran via {node} (RTT: {avg_rtt_val_str}) (accessed via proxy {proxy_display}).")
                                        accessible_from_at_least_one_node = True
                                        node_ping_to_target_successful = True
                                        break
                                    else:
                                        break
                                else: break
                            else: break
                        break
                except requests.exceptions.RequestException as e_poll_req:
                    print(f"  CH_PROXY: RequestException polling {request_id} ({node}) (proxy {proxy_display}): {e_poll_req}")
                    return None
                except Exception as e_poll_other:
                    print(f"  CH_PROXY: Generic error polling {request_id} ({node}) (proxy {proxy_display}): {e_poll_other}")
                    return None
            if node_ping_to_target_successful:
                break
        except requests.exceptions.RequestException as e_init_req:
            print(f"  CH_PROXY: RequestException initiating PING for {ip_to_check_on_checkhost} (node {node}) (proxy {proxy_display}): {e_init_req}")
            if node_idx == 0: return None
        except Exception as e_init_other:
            print(f"  CH_PROXY: Generic error initiating PING for {ip_to_check_on_checkhost} (node {node}) (proxy {proxy_display}): {e_init_other}")
            if node_idx == 0: return None
    if accessible_from_at_least_one_node:
        return False # is ok
    if any_node_test_completed_without_service_error:
        print(f"CH_PROXY: Target IP {ip_to_check_on_checkhost} INACCESSIBLE from Iran based on completed check-host tests (via proxy {proxy_display}).")
        return True
    else:
        print(f"CH_PROXY: No Iranian node completed the test for {ip_to_check_on_checkhost} without service errors (when accessed via proxy {proxy_display}). Concluding issue with proxy or check-host access.")
        return None
def get_public_ipv4(t, port) -> Optional[str]:
    urls = [
        "http://v4.ipv6-test.com/api/myip.php",
        "https://api.ipify.org",
        "https://icanhazip.com"
    ]
    proxy_host = f"127.0.0.{t}"
    proxies = {"http": f"http://{proxy_host}:{port}", "https": f"http://{proxy_host}:{port}"}
    headers = {"Connection": "close", "User-Agent": "Mozilla/5.0"}
    for url in urls:
        print(f"Attempting to fetch public IPv4 address from: {url}...")
        try:
            response = requests.get(url, timeout=10, proxies=proxies, headers=headers)
            response.raise_for_status()
            ip_address_v4 = response.text.strip()
            if ip_address_v4 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address_v4):
                print(f"Successfully fetched IPv4: {ip_address_v4} from {url}")
                return ip_address_v4
            else:
                print(f"Warning: Service {url} returned an invalid response: {ip_address_v4}")
        except requests.exceptions.Timeout:
            print(f"Fetching IPv4 address from {url} timed out.")
        except requests.exceptions.HTTPError as e:
            print(f"Error fetching IPv4 address from {url}: {e}")
        except requests.exceptions.RequestException as e:
            print(f"Request error fetching IPv4 address from {url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred fetching IPv4 from {url}: {e}")
    print("Failed to fetch public IPv4 from all services.")
    return None
def should_retry_ip_api(exception):
    if isinstance(exception, (requests.exceptions.Timeout,
                              requests.exceptions.ConnectionError,
                              requests.exceptions.ConnectTimeout)):
        print(f"Retrying due to network error: {exception}")
        return True
    if isinstance(exception, requests.exceptions.HTTPError):
        if exception.response.status_code >= 500:
            print(f"Retrying due to HTTP server error: {exception}")
            return True
    print(f"Not retrying for error: {exception}")
    return False

def fetch_exit_country_code_via_proxy(proxies_to_use: Optional[dict]) -> str:
    print(f"Fetching EXIT country code using proxy {proxies_to_use.get('http') if proxies_to_use else 'None'}")
    try:
        print(f"  Attempting with ipinfo.io/json...")
        api_url_ipinfo = "https://ipinfo.io/json"
        response_ipinfo = requests.get(api_url_ipinfo, timeout=10, proxies=proxies_to_use)
        response_ipinfo.raise_for_status()
        data_ipinfo = response_ipinfo.json()
        exit_ip = data_ipinfo.get('ip')
        country_code = data_ipinfo.get('country')
        if country_code and isinstance(country_code, str) and len(country_code) == 2 and country_code.isalpha():
            print(f"  Success with ipinfo.io: Exit IP {exit_ip}, Country {country_code.upper()}")
            return country_code.upper()
        else:
            print(f"  Invalid or missing country from ipinfo.io. Response: {data_ipinfo}")
            raise ValueError("Invalid data from ipinfo.io")
    except (requests.exceptions.RequestException, ValueError, json.JSONDecodeError) as e_ipinfo:
        print(f"  Failed with ipinfo.io: {e_ipinfo}. Proceeding to fallback (ipdata.co)...")
    try:
        print(f"  Attempting with ipdata.co (no IP)...")
        if not IPDATA_API_KEY or IPDATA_API_KEY == "YOUR_IPDATA_API_KEY":
            print("  Error: IPDATA_API_KEY not configured for ipdata.co. Skipping.")
            raise ValueError("IPDATA_API_KEY not set")
        api_url_ipdata = f"https://api.ipdata.co?api-key={IPDATA_API_KEY}"
        response_ipdata = requests.get(api_url_ipdata, timeout=10, proxies=proxies_to_use)
        data_ipdata = response_ipdata.json()
        exit_ip = data_ipdata.get('ip')
        country_code = data_ipdata.get('country_code')
        if country_code and isinstance(country_code, str) and len(country_code) == 2 and country_code.isalpha():
            print(f"  Success with ipdata.co: Exit IP {exit_ip}, Country {country_code.upper()}")
            return country_code.upper()
        else:
            # ...
            raise ValueError("Invalid data from ipdata.co")
    except Exception as e_ipdata:
        print(f"  Failed with ipdata.co as well: {e_ipdata}")
        print("  All location services failed. Returning XX.")
        return "XX"
@retry(
    stop_max_attempt_number=3,
    wait_exponential_multiplier=1000,
    wait_exponential_max=10000,
    retry_on_exception=should_retry_ip_api
)
def fetch_country_code_with_fallback(ip_address: str) -> str:
    print(f"Fetching country code for IP: {ip_address}")
    if not ip_address:
        print("no ips found")
        return
    try:
        print(f"  Attempting with ipdata.co...")
        if not IPDATA_API_KEY or IPDATA_API_KEY == "YOUR_IPDATA_API_KEY":
            print("  Error: IPDATA_API_KEY is not configured for ipdata.co. Skipping.")
            raise ValueError("IPDATA_API_KEY not set")
        api_url_ipdata = f"https://api.ipdata.co/{ip_address}?api-key={IPDATA_API_KEY}"
        response_ipdata = requests.get(api_url_ipdata, timeout=10)
        data_ipdata = response_ipdata.json()
        if response_ipdata.status_code != 200:
            error_message_http = data_ipdata.get("message", f"ipdata.co HTTP error {response_ipdata.status_code}")
            if "quota" in error_message_http.lower() or "exceeded" in error_message_http.lower() or \
               "invalid api key" in error_message_http.lower() or response_ipdata.status_code in [401, 403, 429]:
                print(f"  ipdata.co failed (quota/key/permission): {error_message_http}. Triggering fallback.")
                raise ConnectionError(f"Fallback: ipdata.co: {error_message_http}")
            else:
                print(f"  ipdata.co HTTP error for IP {ip_address}: {error_message_http}")
                raise requests.exceptions.HTTPError(error_message_http, response=response_ipdata)
        if "message" in data_ipdata:
            api_error_message = data_ipdata["message"]
            if "quota" in api_error_message.lower() or "exceeded" in api_error_message.lower() or \
               "invalid api key" in api_error_message.lower():
                print(f"  ipdata.co API error (quota/key): {api_error_message}. Triggering fallback.")
                raise ConnectionError(f"Fallback: ipdata.co API: {api_error_message}")
            else:
                print(f"  ipdata.co API message for IP {ip_address}: {api_error_message}")
                raise ValueError(f"ipdata.co API message: {api_error_message}")
        fetched_code_ipdata = data_ipdata.get('country_code')
        if fetched_code_ipdata and isinstance(fetched_code_ipdata, str) and len(fetched_code_ipdata) == 2 and fetched_code_ipdata.isalpha():
            print(f"  Success with ipdata.co: Country is {fetched_code_ipdata.upper()} for IP {ip_address}")
            return fetched_code_ipdata.upper()
        else:
            print(f"  Invalid data from ipdata.co for IP {ip_address}. Response: {data_ipdata}. Triggering fallback.")
            raise ValueError("Invalid data from ipdata.co, triggering fallback.")
    except (requests.exceptions.RequestException, ConnectionError, ValueError, json.JSONDecodeError) as e_ipdata:
        print(f"  Failed with ipdata.co: {type(e_ipdata).__name__} - {str(e_ipdata)[:100]}. Proceeding to fallback (ipinfo.io).")
        try:
            print(f"    Attempting with ipinfo.io...")
            api_url_ipinfo = f"https://ipinfo.io/{ip_address}/json"
            response_ipinfo = requests.get(api_url_ipinfo, timeout=10)
            response_ipinfo.raise_for_status()
            data_ipinfo = response_ipinfo.json()
            if "bogon" in data_ipinfo and data_ipinfo["bogon"] is True:
                print(f"    ipinfo.io reports IP {ip_address} as bogon.")
                raise ValueError(f"IP {ip_address} is a bogon IP (ipinfo.io).")
            fetched_code_ipinfo = data_ipinfo.get('country')
            if fetched_code_ipinfo and isinstance(fetched_code_ipinfo, str) and len(fetched_code_ipinfo) == 2 and fetched_code_ipinfo.isalpha():
                print(f"    Success with ipinfo.io: Country is {fetched_code_ipinfo.upper()} for IP {ip_address}")
                return fetched_code_ipinfo.upper()
            else:
                print(f"    Invalid or missing country_code from ipinfo.io for IP {ip_address}. Response: {data_ipinfo}")
                raise ValueError(f"Invalid or missing country code from ipinfo.io: '{fetched_code_ipinfo}'")
        except (requests.exceptions.RequestException, ValueError, json.JSONDecodeError) as e_ipinfo:
            print(f"    Failed with ipinfo.io as well: {type(e_ipinfo).__name__} - {str(e_ipinfo)[:100]}")
            raise ValueError(f"Both ipdata.co and ipinfo.io failed for IP {ip_address}.") from e_ipinfo
def get_ip_details(ip_address: Optional[str], original_config_str: str,proxies_to_use: Optional[dict]):
    global FIN_CONF
    print(f"DEBUG_IP_DETAILS: Entered get_ip_details. IP: '{ip_address}', Config: '{original_config_str[:50]}...'")
    country_code = "XX"
    if ip_address:
        try:
            country_code = fetch_exit_country_code_via_proxy(proxies_to_use)
            print(f"Successfully fetched country code: {country_code} for IP {ip_address} after retries.")
        except ValueError as e:
            print(f"{e}. Using default XX.")
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error from ip-api (after retries) for {ip_address}: {e}. Using default XX.")
        except requests.exceptions.Timeout:
            print(f"Final timeout fetching IP details for {ip_address}. Using default XX.")
        except requests.exceptions.RequestException as e:
            print(f"Final network error requesting ip-api for {ip_address}: {e}. Using default XX.")
        except json.JSONDecodeError:
            print(f"Final error parsing JSON response from ip-api for {ip_address}. Using default XX.")
        except Exception as e:
            print(f"Final unexpected error fetching country code for {ip_address}: {e}. Using default XX.")
    else:
        print(f"IP address not provided for config {original_config_str.strip()[:30]}... Using default country code XX.")
    config_stripped = original_config_str.strip()
    processed_as_vmess_successfully = False
    if config_stripped.startswith("vmess://"):
        try:
            vmess_link_parts = config_stripped.replace("vmess://", "", 1).split("#", 1)
            base64_encoded_part = vmess_link_parts[0]
            missing_padding = len(base64_encoded_part) % 4
            if missing_padding:
                base64_encoded_part += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(base64_encoded_part)
            decoded_json_str = decoded_bytes.decode('utf-8')
            vmess_data = json.loads(decoded_json_str)
            original_ps = vmess_data.get("ps", "")
            if not isinstance(original_ps, str):
                original_ps = str(original_ps)
            if not original_ps.strip():
                add = vmess_data.get("add", "unknown_host")
                port = vmess_data.get("port", "0")
                original_ps = f"vmess_{add}_{port}"
                print(f"Field 'ps' in vmess config was empty or non-existent, using default name '{original_ps}' for internal 'ps'.")
            new_ps = f"{original_ps.strip()}::{country_code}"
            vmess_data["ps"] = new_ps
            updated_json_str = json.dumps(vmess_data, ensure_ascii=False, separators=(',', ':'))
            updated_base64_bytes = base64.b64encode(updated_json_str.encode('utf-8'))
            updated_base64_str = updated_base64_bytes.decode('utf-8').rstrip("=")
            final_config_string = f"vmess://{updated_base64_str}"
            print(f"DEBUG (Vmess): Final config with updated 'ps': {final_config_string}")
            FIN_CONF.append(final_config_string)
            processed_as_vmess_successfully = True
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"Error decoding base64 or utf-8 for vmess config: {config_stripped[:50]}... Error: {e}. Using generic tagging for this vmess link.")
        except json.JSONDecodeError as e:
            print(f"Error parsing internal JSON for vmess config: {config_stripped[:50]}... Error: {e}. Using generic tagging for this vmess link.")
        except Exception as e:
            print(f"Unexpected error during specialized vmess config processing {config_stripped[:50]}...: {e}. Using generic tagging for this vmess link.")
    if not processed_as_vmess_successfully:
        parts = config_stripped.split("#", 1)
        config_base = parts[0]
        original_tag_encoded = parts[1] if len(parts) > 1 else ""
        try:
            original_tag_decoded = urllib.parse.unquote(original_tag_encoded)
        except Exception:
            original_tag_decoded = original_tag_encoded
        if not original_tag_decoded.strip():
            protocol_match = re.match(r"^\w+://", config_base)
            protocol_name = protocol_match.group(0).replace("://","").lower() if protocol_match else "config"
            server_part_for_tag = config_base.split("://", 1)[-1].split("?",1)[0].split("#",1)[0]
            host_info_candidate = server_part_for_tag.split('@')[-1]
            address_match = re.match(r"([^:]+)(?::(\d+))?", host_info_candidate)
            server_brief = "unknown_server"
            if address_match:
                host_for_tag = address_match.group(1)
                port_for_tag = address_match.group(2)
                server_brief = f"{host_for_tag}"
                if port_for_tag:
                    server_brief += f"_{port_for_tag}"
            elif host_info_candidate and len(host_info_candidate.split(':')[0]) < 50 :
                 server_brief = host_info_candidate.split(':')[0]
            original_tag_decoded = f"{protocol_name}_{server_brief}"
            if config_stripped.startswith("vmess://"):
                 print(f"Original tag for vmess config (specialized processing failed) was empty, using '{original_tag_decoded}' for generic tagging.")
            else:
                 print(f"Original tag for '{protocol_name}' config was empty or non-existent, using '{original_tag_decoded}'.")
        new_tag_unencoded = f"{original_tag_decoded.strip()}::{country_code}"
        new_tag_encoded = urllib.parse.quote(new_tag_unencoded)
        final_config_string = f"{config_base}#{new_tag_encoded}"
        print(f"DEBUG (Generic/Fallback): Final config with generic tag: {final_config_string}")
        FIN_CONF.append(final_config_string)
def ping_all():
    print("igo")
    xray_abs = os.path.abspath("xray/xray")
    def s_xray(conf_path,t):
        proc=subprocess.Popen([xray_abs, 'run', '-c', conf_path], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process_manager.add_process(f"xray_{t}", proc.pid)
    def s_hy2(path_file,t):
        hy=subprocess.Popen (['hy2/hysteria', 'client' ,'-c' , path_file], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process_manager.add_process(f"hysteria_{t}", hy.pid)
    def load_config():
        try:
            with open(TEXT_PATH, "r") as f:
                try:
                    content = f.read()
                    file_data = json.loads(content)
                    return file_data, True
                except json.JSONDecodeError:
                    lines = content.splitlines()
                    return [line for line in lines if line.strip()], False
        except FileNotFoundError:
            print(f"ERROR: File not found at {TEXT_PATH}")
            return [], False
        except Exception as e:
            print(f"ERROR: Unexpected error loading config from {TEXT_PATH}: {e}")
            return [], False
    def update_ip_addresses(input_dict,t):
        def update_value(value):
            if isinstance(value, str):
                if "127.0.0." in value:
                    return f"127.0.0.{str(t)}"
            elif isinstance(value, list):
                return [update_value(item) for item in value]
            elif isinstance(value, dict):
                return update_ip_addresses(value,t)
            return value
        return {key: update_value(value) for key, value in input_dict.items()}
    def process_ping(i:str, t,counter=2) :
        global FIN_CONF
        print(i)
        while t > 100:
            t-=100
        path_test_file=f"xray/config_test_ping{'' if t==0 else str(t)}.json"
        hy2_path_test_file=f"hy2/config{'' if t==0 else str(t)}.yaml"
        result="-1"
        is_wrong = False
        with open(path_test_file, "w") as f:
            try:
                if not is_dict:
                    f.write(parse_configs(i, cv=t+2, hy2_path=hy2_path_test_file))
                else:
                    json.dump(update_ip_addresses(i, t+2), f)
            except Exception as E:
                is_wrong = True
                print(E)
        if not is_wrong:
            with open(path_test_file, "r") as f:
                temp3 = json.load(f)
            port = temp3["inbounds"][1]["port"]
            if not is_dict:
                if i.startswith("hy2://") or i.startswith("hysteria2://"):
                    th3h = threading.Thread(target=s_hy2,args=(hy2_path_test_file,t,))
                    th3h.start()
            th3 = threading.Thread(target=s_xray,args=(path_test_file,t,))
            th3.start()
            time.sleep(3)
            os.remove(path_test_file)
            if os.path.exists(hy2_path_test_file):
                os.remove(hy2_path_test_file)
            proxies = {"http": f"http://127.0.0.{t+2}:{port}",
                            "https": f"http://127.0.0.{t+2}:{port}"}
            @retry(stop_max_attempt_number=3, wait_fixed=500, retry_on_exception=lambda x: isinstance(x, Exception))
            def pingg():
                try:
                    url = test_link_
                    headers = {"Connection": "close"}
                    start = time.time()
                    response = requests.get(url, proxies=proxies, timeout=10, headers=headers)
                    elapsed = (time.time() - start) * 1000
                    if response.status_code == 204 or (response.status_code == 200 and len(response.content) == 0):
                        return f"{int(elapsed)}"
                    else:
                        if response.status_code == 503:
                            raise IOError("Connection test error, check your connection or ping again ...")
                        else:
                            raise IOError(f"Connection test error, status code: {response.status_code}")
                except RequestException as e:
                    print(f"testConnection RequestException: {e}")
                    return "-1"
                except Exception as e:
                    print(f"testConnection Exception: {e}")
                    return "-1"
            try:
                result = pingg()
            except Exception:
                result = "-1"
            if result !="-1":
                if CHECK_LOC:
                    public_ip = get_public_ipv4(t+2, port)
                    if CHECK_IRAN:
                        if is_ip_accessible_from_iran_via_check_host(public_ip,proxies):
                            get_ip_details(public_ip,i,proxies)
                    else:
                        get_ip_details(public_ip,i,proxies)
                else:
                    if CHECK_IRAN:
                        public_ip = get_public_ipv4(t+2, port)
                        if is_ip_accessible_from_iran_via_check_host(public_ip,proxies):
                            FIN_CONF.append(i)
                    else:
                        FIN_CONF.append(i)
            if not is_dict:
                if i.startswith("hy2://") or i.startswith("hysteria2://"):
                    process_manager.stop_process(f"hysteria_{t}")
            process_manager.stop_process(f"xray_{t}")
    sun_nms, is_dict = load_config()
    copy_in_sus_nms=sun_nms
    with ThreadPoolExecutor(max_workers=TH_MAX_WORKER) as executor:
        futures = [executor.submit(process_ping, i, t) for t, i in enumerate(sun_nms)]
    if is_dict:
        with open(TEXT_PATH, "w") as f:
            json.dump(copy_in_sus_nms, f, indent=2, ensure_ascii=False)
    else:
        with open(TEXT_PATH, "w") as f:
            f.writelines(f"{line}\n" for line in copy_in_sus_nms)
if  len(LINK_PATH) != 0:
    for link  in LINK_PATH:
        if link.startswith("http://") or link.startswith("https://"):
                response = requests.get(link, timeout=15)
                response.raise_for_status()
                try:
                    json_data = response.json()
                    content_to_write = json.dumps(json_data, indent=4, ensure_ascii=False)
                except requests.exceptions.JSONDecodeError:
                    content_to_write = response.text
                with open(TEXT_PATH, "w") as f:
                    f.write(content_to_write)
ping_all()
with open(FIN_PATH,"w") as f:
    try:
        if FIN_CONF:
            if isinstance(FIN_CONF[0], dict):
                json.dump(FIN_CONF, f, indent=2, ensure_ascii=False)
            else:
                f.writelines(f"{line.strip()}\n" for line in FIN_CONF if line.strip())
        else:
            print(f"No successful configs found. Writing empty {FIN_PATH}.")
    except Exception as e:
        print(f"Unexpected error writing to {FIN_PATH}: {e}")
exit()
