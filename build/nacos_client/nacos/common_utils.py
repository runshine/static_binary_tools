import atexit
import socket
import re
import subprocess
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import signal
import fcntl
import json
from urllib.parse import urlencode
import requests
import time
import struct


def get_ipv4_addresses():
    ipv4_addresses = []

    # 获取所有网络接口的原始信息
    if sys.platform.startswith('win'):
        # Windows 系统
        try:
            # 获取IP配置信息
            output = subprocess.check_output(['ipconfig', '/all'], encoding='oem')
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []

        # 解析每个网络接口的IPv4地址
        interface_blocks = re.split(r'\r?\n\r?\n', output)
        for block in interface_blocks:
            if 'IPv4 Address' not in block:
                continue
            # 查找所有IPv4地址
            matches = re.finditer(
                r'IPv4 Address[ .:]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
                block,
                re.IGNORECASE
            )
            for match in matches:
                ip = match.group(1)
                if not ip.startswith('127.'):
                    ipv4_addresses.append(ip)

    else:
        # Linux/macOS 系统
        try:
            # 优先使用 ip 命令
            env = dict(os.environ)
            env['LC_ALL'] = 'C'  # 确保输出为英文
            output = subprocess.check_output(['ip', '-4', 'addr'],
                                             stderr=subprocess.DEVNULL,
                                             encoding='utf-8',
                                             env=env)
            # 解析每行输出
            for line in output.splitlines():
                if 'inet' in line:
                    # 提取IP地址 (格式: inet 192.168.1.10/24 ...)
                    match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if match:
                        ip = match.group(1)
                        if not ip.startswith('127.'):
                            ipv4_addresses.append(ip)
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                # 回退到 ifconfig 命令
                env = dict(os.environ)
                env['LC_ALL'] = 'C'
                output = subprocess.check_output(['ifconfig'],
                                                 encoding='utf-8',
                                                 env=env)
                # 解析每个接口的IPv4地址
                for line in output.splitlines():
                    if 'inet ' in line and 'inet6' not in line:
                        match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if match:
                            ip = match.group(1)
                            if not ip.startswith('127.'):
                                ipv4_addresses.append(ip)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

    return ipv4_addresses


def translate_ipv4_list_to_map(ipv4_list):
    res = {}
    count = 0
    for ip in ipv4_list:
        res[f"ipv4_address_{count}"] = ip
        count =  count + 1
    return res


def setup_logger(log_file):
    # 创建日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # 设置默认日志级别为INFO

    # 创建文件处理器 - 限制单个文件最大5MB，保留3个备份
    file_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,          # 保留3个备份文件
        encoding='utf-8'
    )
    # 创建日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 应用格式到处理器
    file_handler.setFormatter(formatter)
    # 添加处理器到记录器
    logger.addHandler(file_handler)
    return logger


def setup_grace_exit(exit_fun):
    signal.signal(signal.SIGINT, exit_fun)  # Ctrl+C
    signal.signal(signal.SIGTERM, exit_fun)  # kill 命令


def prevent_multiple_running(lock_file_path):
    lock_file = open(lock_file_path, 'w')
    try:
        # 尝试获取独占锁（非阻塞模式）
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        print("Another instance is already running. Exiting.")
        sys.exit(1)
    return lock_file

g_lock_file = None


def setup_singal_runner(pid_lock_file):
    global g_lock_file
    g_lock_file = prevent_multiple_running(pid_lock_file)


@atexit.register
def global_cleanup():
    print("\n全局清理：释放所有资源")
    if g_lock_file:
        g_lock_file.close()


g_nacos_server_ip = None
g_nacos_server_port = None
g_nacos_heartbeat_time = None


def setup_nacos_server(server_ip = None,server_port = None,heartbeat_time = 5):
    global g_nacos_server_ip,g_nacos_server_port,g_nacos_heartbeat_time
    if server_port is None or server_port is None:
        ip_address = get_sothoth_ip_address()
        g_nacos_server_ip = re.findall(r"^(\d+\.\d+\.)\d+\.\d+",ip_address)[0] + "0.2"
        g_nacos_server_port = "8848"
        g_nacos_heartbeat_time = heartbeat_time
    else:
        g_nacos_server_ip = server_ip
        g_nacos_server_port = server_port
        g_nacos_heartbeat_time = heartbeat_time
    logging.getLogger().info("start setup nacos server, server is: {}:{}".format(g_nacos_server_ip,g_nacos_server_port))


def nacos_service_register(service_name,service_ip,service_port,metadata = None):
    global g_nacos_server_ip,g_nacos_server_port
    url = f"http://{g_nacos_server_ip}:{g_nacos_server_port}/nacos/v3/client/ns/instance"
    if metadata is None:
        metadata = {}
    params = {"serviceName":service_name,
              "ip":service_ip,
              "port":service_port,
              "weight":"1.0",
              "enabled":"true",
              "healthy":"true",
              "ephemeral":"true",
              "metadata": json.dumps(metadata)
              }
    if 'service_name' in metadata.keys():
        params["clusterName"] = metadata['service_name']
    url = "{}?{}".format(url,urlencode(params))
    try:
        res = requests.post(url)
        logging.getLogger().info(f"向nacos注册中心，发起服务注册请求，注册响应状态： {res.status_code}, {service_name}-->{service_ip}:{service_port}")
        if res.status_code != 200:
            logging.getLogger().warning(f"response not ok: {res.json()}" )
            return False
        return True
    except Exception as e:
        return False


def nacos_query_service(service_name):
    global g_nacos_server_ip,g_nacos_server_port
    url = f"http://{g_nacos_server_ip}:{g_nacos_server_port}/nacos/v3/client/ns/instance/list?serviceName={service_name}&pageNo=1&pageSize=100"
    try:
        res = requests.get(url)
        if res.status_code != 200:
            logging.getLogger().warning(f"response not ok: {res.json()}" )
            return None
        return res.json()
    except Exception as e:
        return None


#服务检测（每5秒心跳一次）
def nacos_service_beat(service_name,service_ip,service_port):
    global g_nacos_server_ip,g_nacos_server_port
    url = f"http://{g_nacos_server_ip}:{g_nacos_server_port}/nacos/v1/ns/instance/beat?serviceName={service_name}&ip={service_ip}&port={service_port}"
    try:
        res = requests.put(url)
        logging.getLogger().info(f"已注册服务，执行心跳服务，续期服务响应状态： {res.status_code}, {service_name}-->{service_ip}:{service_port}")
        if res.status_code != 200:
            logging.getLogger().warning(f"response not ok: {res.json()}")
            return False
        return True
    except Exception as e:
        return False


def get_ip_by_device(ifname):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(ifname[:15],'utf-8')))[20:24])
    except Exception as e:
        return ""


def is_valid_ipv4(ip):
    if len(ip.strip()) == 0:
        return False
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    regex = re.compile(pattern)
    if regex.match(ip):
        return True
    else:
        return False


def get_sothoth_ip_address():
    ip_address = get_ip_by_device("tap-sothoth")
    while not is_valid_ipv4(ip_address):
        logging.getLogger().warning("wait tap-sothoth avaiable")
        time.sleep(5)
        ip_address = get_ip_by_device("tap-sothoth")
    return ip_address


def start_nacos_service(service_name,port,metadata = None, health_check_fun=None,*args):
    register_retry = 99999
    service_check_interval = 12
    if metadata is None:
        metadata = {}
    metadata['service_name'] = service_name
    metadata['service_port'] = port
    metadata['hostname'] = socket.gethostname()
    ip_address = get_sothoth_ip_address()
    service_name = "{}-{}".format(socket.gethostname(),ip_address)
    while register_retry > 0 and not nacos_service_register(service_name,ip_address,port,metadata):
        register_retry = register_retry -1
        logging.getLogger().warning(f"Failed register to nacos server, retry: {register_retry}")
        time.sleep(10)
    if register_retry == 0:
        logging.getLogger().warning("Failed register to nacos server, unable to continue")
    service_check_count = 0
    last_health_check_ret = True
    while True:
        ip_address = get_sothoth_ip_address()
        service_name = "{}-{}".format(socket.gethostname(),ip_address)
        time.sleep(g_nacos_heartbeat_time)
        if health_check_fun is not None:
            health_check_ret = health_check_fun(*args)
        else:
            health_check_ret = True
        if last_health_check_ret and health_check_ret:
            pass
        elif not health_check_ret:
            logging.getLogger().warning(f"Check health failed: {metadata['service_name']}")
            last_health_check_ret = health_check_ret
            continue
        elif not last_health_check_ret and health_check_ret:
            logging.getLogger().warning(f"Check health success after failed, try to re-register: {metadata['service_name']}")
            nacos_service_register(service_name,ip_address,port,metadata)
            last_health_check_ret = health_check_ret
            continue
        #normal sence, try normal
        last_health_check_ret = True
        nacos_service_beat(service_name,ip_address,port)
        service_check_count = service_check_count + 1
        if service_check_count >= service_check_interval:
            service_check_count = 0
            if nacos_query_service(service_name) is None:
                logging.getLogger().warning(f"Failed check service exist, retry register it: {service_name}")
                nacos_service_register(service_name,ip_address,port,metadata)
            else:
                logging.getLogger().info(f"Check service: {service_name} exist ok")
                nacos_service_register(service_name,ip_address,port,metadata)


def check_tcp_port_is_listen(tcp_port):
    """
    检测指定端口是否在Linux系统上被监听

    参数:
        port (int): 要检测的端口号
        host (str): 检测的主机地址 (默认: 127.0.0.1)
        timeout (float): 连接超时时间(秒) (默认: 1.0)

    返回:
        bool: True表示端口已被监听，False表示未被监听
    """
    timeout = 1.0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(("127.0.0.1", tcp_port))
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except Exception as e:
        return False