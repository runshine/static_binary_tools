import threading
from common_utils import *
from urllib.parse import urlparse

def start_ttyd_service():
    start_nacos_service("ttyd","11198",translate_ipv4_list_to_map(get_ipv4_addresses()),check_tcp_port_is_listen,11198)


def start_openssh_service():
    start_nacos_service("sshd","11192",None,check_tcp_port_is_listen,11192)


def start_nginx_proxy_service():
    start_nacos_service("nginx-proxy","11199",None,check_tcp_port_is_listen,11199)


def start_docker_service():
    start_nacos_service("dockerd","11191",None,check_tcp_port_is_listen,11191)


def start_frida_server_service():
    start_nacos_service("frida-server","11189",None,check_tcp_port_is_listen,11189)


def start_rpcapd_service():
    start_nacos_service("rpcapd","11188",None,check_tcp_port_is_listen,11199)


def graceful_exit(signum, frame):
    global server_should_stop
    logging.getLogger().warning(f"start graceful_exit, recv signum: {signum}" )
    server_should_stop = True
    sys.exit(0)


def start_nacos(UPSTREAM_SERVER_URL,WORKSPACE_ID):
    parsed = urlparse(UPSTREAM_SERVER_URL)
    protocol = parsed.scheme
    host = parsed.hostname
    port = parsed.port
    setup_nacos_server(server_ip=host,server_port=int(port),heartbeat_time=5,workspace_id=WORKSPACE_ID)
    ttyd_thread = threading.Thread(target=start_ttyd_service)
    ttyd_thread.start()
    sshd_thread = threading.Thread(target=start_openssh_service)
    sshd_thread.start()
    nginx_proxy_thread = threading.Thread(target=start_nginx_proxy_service)
    nginx_proxy_thread.start()
    docker_thread = threading.Thread(target=start_docker_service)
    docker_thread.start()
    frida_server_thread = threading.Thread(target=start_frida_server_service)
    frida_server_thread.start()
    rpcapd_thread = threading.Thread(target=start_rpcapd_service)
    rpcapd_thread.start()
    ttyd_thread.join()
    sshd_thread.join()
    nginx_proxy_thread.join()
    docker_thread.join()
    frida_server_thread.join()
    rpcapd_thread.join()
