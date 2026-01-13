import os
import sys
import threading
from common_utils import *
from flask import Flask, jsonify, request, send_file, abort, redirect

app = Flask(__name__)

server_should_stop = False


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


def start_nacos():
    setup_nacos_server(server_ip=UPSTREAM_SERVER,server_port=8848,heartbeat_time=5)
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



if __name__ == "__main__":
    setup_grace_exit(graceful_exit)
    ROOT_DIR=os.getenv("ROOT_DIR")
    UPSTREAM_SERVER=os.getenv("UPSTREAM_SERVER")
    if UPSTREAM_SERVER is None or len(UPSTREAM_SERVER) == 0:
        print(f"UPSTREAM_SERVER env check failed: {UPSTREAM_SERVER}")
        exit(-1)
    NACOS_SERVER = UPSTREAM_SERVER
    setup_logger(os.path.join(ROOT_DIR,"var/log/nacos_client.log"))
    setup_singal_runner(os.path.join(ROOT_DIR,"var/run/nacos_client.lock"))
    threading.Thread(target=start_nacos).start()
    app.run(host="0.0.0.0",port="11190",debug=False,threaded=True)