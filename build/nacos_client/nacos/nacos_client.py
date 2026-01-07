import os
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
    server_should_stop = True


def start_nacos():
    setup_nacos_server()
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


@app.route('/nginx/tcp/add/<local_port>/<remote_host>/<remote_port>', methods=['GET'])
def add_nginx_tcp_mapping(local_port,remote_host,remote_port):
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    target_file = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/tcp_mapping_{local_port}.conf")
    if os.path.exists(target_file):
        return abort(403)
    with open(target_file,"w") as f:
        f.write('''
server {{
        listen {} ;                       # 监听UDP端口1194
        proxy_pass {}:{};    # 目标服务器地址
        proxy_timeout 60s;                          # 超时时间（按需调整）
        #proxy_responses 0;                         # 适用于单方向UDP流（如VPN）
    }}  
        '''.format(local_port,remote_host,remote_port))
    os.system(os.path.join(NACOS_ROOT_DIR,"../script/reload_nginx.sh"))
    return jsonify({"result":"ok"})


@app.route('/nginx/tcp/del/<local_port>', methods=['GET'])
def del_nginx_tcp_mapping(local_port):
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    target_file = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/tcp_mapping_{local_port}.conf")
    if not os.path.exists(target_file):
        return abort(403)
    os.unlink(target_file)
    os.system(os.path.join(NACOS_ROOT_DIR,"../script/reload_nginx.sh"))
    return jsonify({"result":"ok"})


@app.route('/nginx/tcp/list', methods=['GET'])
def list_nginx_tcp_mapping():
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    nginx_config_dir = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/")
    result = []
    for file in os.listdir(nginx_config_dir):
        if os.path.isfile(os.path.join(nginx_config_dir,file)) and file.startswith("tcp_mapping_") and file.endswith(".conf"):
            with open(os.path.join(nginx_config_dir,file)) as f:
                content = ''.join(f.readlines())
            local_port = re.findall(r'listen\s+(\d+)\s+;',content)[0]
            remote_host = re.findall(r'proxy_pass\s+(\S+)\s*:',content)[0]
            remote_port = re.findall(r'proxy_pass\s+\S+\s*:(\d+)',content)[0]
            result.append({"local_port": local_port,"remote_host": remote_host,"remote_port":remote_port})
    return jsonify({"result": "ok", "data": result})


@app.route('/nginx/udp/add/<local_port>/<remote_host>/<remote_port>', methods=['GET'])
def add_nginx_udp_mapping(local_port,remote_host,remote_port):
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    target_file = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/udp_mapping_{local_port}.conf")
    if os.path.exists(target_file):
        return abort(403)
    with open(target_file,"w") as f:
        f.write('''
    server {{
            listen {} udp reuseport;                       # 监听UDP端口1194
            proxy_pass {}:{};    # 目标服务器地址
            proxy_timeout 60s;                          # 超时时间（按需调整）
            #proxy_responses 0;                         # 适用于单方向UDP流（如VPN）
        }}  
            '''.format(local_port,remote_host,remote_port))
    os.system(os.path.join(NACOS_ROOT_DIR,"../script/reload_nginx.sh"))
    return jsonify({"result":"ok"})


@app.route('/nginx/udp/del/<local_port>', methods=['GET'])
def del_nginx_udp_mapping(local_port):
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    target_file = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/udp_mapping_{local_port}.conf")
    if not os.path.exists(target_file):
        return abort(403)
    os.unlink(target_file)
    os.system(os.path.join(NACOS_ROOT_DIR,"../script/reload_nginx.sh"))
    return jsonify({"result":"ok"})


@app.route('/nginx/udp/list', methods=['GET'])
def list_nginx_udp_mapping():
    global NACOS_ROOT_DIR
    logging.getLogger().debug(f"NACOS_ROOT_DIR: {NACOS_ROOT_DIR}")
    nginx_config_dir = os.path.join(NACOS_ROOT_DIR,f"../nginx/conf/stream.d/")
    result = []
    for file in os.listdir(nginx_config_dir):
        if os.path.isfile(os.path.join(nginx_config_dir,file)) and file.startswith("udp_mapping_") and file.endswith(".conf"):
            with open(os.path.join(nginx_config_dir,file)) as f:
                content = ''.join(f.readlines())
            local_port = re.findall(r'listen\s+(\d+)\s+udp',content)[0]
            remote_host = re.findall(r'proxy_pass\s+(\S+)\s*:',content)[0]
            remote_port = re.findall(r'proxy_pass\s+\S+\s*:(\d+)',content)[0]
            result.append({"local_port": local_port,"remote_host": remote_host,"remote_port":remote_port})

    return jsonify({"result": "ok", "data": result})


if __name__ == "__main__":
    setup_grace_exit(graceful_exit)
    NACOS_ROOT_DIR=os.getenv("NACOS_ROOT_DIR")
    UPSTREAM_SERVER=os.getenv("UPSTREAM_SERVER")
    if NACOS_ROOT_DIR is None or not os.path.exists(NACOS_ROOT_DIR):
        print(f"NACOS_ROOT_DIR env check failed: {NACOS_ROOT_DIR}")
        exit(-1)
    if UPSTREAM_SERVER is None or len(UPSTREAM_SERVER) == 0:
        print(f"UPSTREAM_SERVER env check failed: {UPSTREAM_SERVER}")
        exit(-1)
    NACOS_SERVER = UPSTREAM_SERVER
    setup_logger(os.path.join(NACOS_ROOT_DIR,"log/nacos_client.log"))
    setup_singal_runner(os.path.join(NACOS_ROOT_DIR,"run/nacos_client.lock"))
    threading.Thread(target=start_nacos).start()
    app.run(host="0.0.0.0",port="11190",debug=False,threaded=True)