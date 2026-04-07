#!/usr/bin/env python3
"""
Docker Compose服务管理WEB服务器
支持服务管理、升级、健康检查等功能
"""

import os
import sys
import json
import yaml
import sqlite3
import logging
import argparse
import subprocess
import tempfile
import zipfile
import tarfile
import shutil
import shlex
import time
import uuid
import hashlib
import signal
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import psutil
import platform
import socket
import mimetypes
import re
import configparser

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_sock import Sock
import docker
from docker.errors import DockerException, APIError
import requests
from common_utils import setup_logger,setup_grace_exit,get_sothoth_ip_address
from nacos_client_monitor import start_nacos,graceful_exit
from urllib.parse import urlparse, unquote

# 全局变量
app = Flask(__name__)
CORS(app)
sock = Sock(app)
config = {}
db_conn = None
docker_client = None
server_should_stop = False
logger = None
VERSION_FILE = Path(__file__).resolve().parent / 'version.json'
_services_cache_lock = threading.Lock()
_services_cache: Dict[str, Any] = {
    'payload': None,
    'ts': 0.0,
    'refreshing': False,
    'last_error': '',
}

# ===================== 系统信息收集相关类 =====================

@dataclass
class CPUInfo:
    """CPU信息"""
    physical_cores: int
    logical_cores: int
    usage_percent: float
    model: str
    architecture: str
    frequency_current: float
    frequency_max: float
    load_average_1min: float
    load_average_5min: float
    load_average_15min: float

@dataclass
class MemoryInfo:
    """内存信息"""
    total: int
    available: int
    used: int
    free: int
    usage_percent: float
    swap_total: int
    swap_used: int
    swap_free: int
    swap_usage_percent: float

@dataclass
class DiskInfo:
    """磁盘信息"""
    device: str
    mountpoint: str
    fstype: str
    total: int
    used: int
    free: int
    usage_percent: float
    read_bytes: int
    write_bytes: int
    read_count: int
    write_count: int

@dataclass
class NetworkInterfaceInfo:
    """网络接口信息"""
    name: str
    ip_address: str
    netmask: str
    broadcast: str
    mac_address: str
    is_up: bool
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int

@dataclass
class ProcessInfo:
    """进程信息"""
    pid: int
    name: str
    status: str
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    memory_vms: int
    create_time: float
    cmdline: List[str]

@dataclass
class DockerInfo:
    """Docker信息"""
    version: str
    api_version: str
    containers_total: int
    containers_running: int
    containers_stopped: int
    containers_paused: int
    images_total: int
    images_size: int
    volumes_total: int
    networks_total: int
    is_docker_available: bool
    docker_root_dir: str

@dataclass
class SystemInfo:
    """系统信息汇总"""
    timestamp: str
    hostname: str
    os_name: str
    os_version: str
    os_release: str
    kernel_version: str
    architecture: str
    boot_time: str
    uptime: int
    cpu: CPUInfo
    memory: MemoryInfo
    disks: List[DiskInfo]
    network_interfaces: List[NetworkInterfaceInfo]
    docker: DockerInfo
    processes_top: List[ProcessInfo]

@dataclass
class AuthResult:
    """鉴权结果"""
    authenticated: bool
    message: str
    timestamp: str
    token_provided: str
    token_length: int
    token_match: bool
    client_ip: str
    user_agent: str
    request_method: str
    request_path: str


@dataclass
class ExecSession:
    """WebSocket 终端会话。"""
    process: subprocess.Popen
    resolved_container: str
    mode: str
    detach_sequence: bytes = b''

class SystemInfoCollector:
    """系统信息收集器"""

    def __init__(self, docker_client=None):
        self.docker_client = docker_client

    def get_system_info(self) -> SystemInfo:
        """获取完整的系统信息"""
        return SystemInfo(
            timestamp=datetime.now().isoformat(),
            hostname=self._get_hostname(),
            os_name=self._get_os_name(),
            os_version=self._get_os_version(),
            os_release=self._get_os_release(),
            kernel_version=self._get_kernel_version(),
            architecture=self._get_architecture(),
            boot_time=self._get_boot_time(),
            uptime=self._get_uptime(),
            cpu=self._get_cpu_info(),
            memory=self._get_memory_info(),
            disks=self._get_disks_info(),
            network_interfaces=self._get_network_interfaces_info(),
            docker=self._get_docker_info(),
            processes_top=self._get_top_processes(limit=10)
        )

    def _get_hostname(self) -> str:
        """获取主机名"""
        return socket.gethostname()

    def _get_os_name(self) -> str:
        """获取操作系统名称"""
        return platform.system()

    def _get_os_version(self) -> str:
        """获取操作系统版本"""
        try:
            if platform.system() == "Linux":
                # 尝试读取/etc/os-release文件
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')
            return platform.version()
        except:
            return platform.version()

    def _get_os_release(self) -> str:
        """获取操作系统发行版"""
        try:
            if platform.system() == "Linux":
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('VERSION_ID='):
                            return line.split('=')[1].strip().strip('"')
        except:
            pass
        return ""

    def _get_kernel_version(self) -> str:
        """获取内核版本"""
        return platform.release()

    def _get_architecture(self) -> str:
        """获取系统架构"""
        return platform.machine()

    def _get_boot_time(self) -> str:
        """获取启动时间"""
        boot_timestamp = psutil.boot_time()
        return datetime.fromtimestamp(boot_timestamp).isoformat()

    def _get_uptime(self) -> int:
        """获取运行时间（秒）"""
        boot_timestamp = psutil.boot_time()
        return int(time.time() - boot_timestamp)

    def _get_cpu_info(self) -> CPUInfo:
        """获取CPU信息"""
        # 获取CPU频率（需要psutil 5.6.0+）
        freq = psutil.cpu_freq()
        freq_current = freq.current if freq else 0
        freq_max = freq.max if freq else 0

        # 获取CPU型号（Linux特定）
        cpu_model = "Unknown"
        if platform.system() == "Linux":
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('model name'):
                            cpu_model = line.split(':')[1].strip()
                            break
            except:
                cpu_model = platform.processor()
        else:
            cpu_model = platform.processor()

        # 获取平均负载（Linux特定）
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)

        return CPUInfo(
            physical_cores=psutil.cpu_count(logical=False),
            logical_cores=psutil.cpu_count(logical=True),
            usage_percent=psutil.cpu_percent(interval=0.1),
            model=cpu_model,
            architecture=platform.machine(),
            frequency_current=freq_current,
            frequency_max=freq_max,
            load_average_1min=load_avg[0] if len(load_avg) > 0 else 0,
            load_average_5min=load_avg[1] if len(load_avg) > 1 else 0,
            load_average_15min=load_avg[2] if len(load_avg) > 2 else 0
        )

    def _get_memory_info(self) -> MemoryInfo:
        """获取内存信息"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return MemoryInfo(
            total=memory.total,
            available=memory.available,
            used=memory.used,
            free=memory.free,
            usage_percent=memory.percent,
            swap_total=swap.total,
            swap_used=swap.used,
            swap_free=swap.free,
            swap_usage_percent=swap.percent
        )

    def _get_disks_info(self) -> List[DiskInfo]:
        """获取磁盘信息"""
        disks = []

        # 获取磁盘分区信息
        partitions = psutil.disk_partitions(all=False)

        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                io_counters = psutil.disk_io_counters(perdisk=True)

                disk_io = io_counters.get(partition.device, None) if io_counters else None

                disk_info = DiskInfo(
                    device=partition.device,
                    mountpoint=partition.mountpoint,
                    fstype=partition.fstype,
                    total=usage.total,
                    used=usage.used,
                    free=usage.free,
                    usage_percent=usage.percent,
                    read_bytes=disk_io.read_bytes if disk_io else 0,
                    write_bytes=disk_io.write_bytes if disk_io else 0,
                    read_count=disk_io.read_count if disk_io else 0,
                    write_count=disk_io.write_count if disk_io else 0
                )
                disks.append(disk_info)
            except Exception as e:
                logger.warning(f"获取磁盘 {partition.mountpoint} 信息失败: {e}")
                continue

        return disks

    def _get_network_interfaces_info(self) -> List[NetworkInterfaceInfo]:
        """获取网络接口信息"""
        interfaces = []

        # 获取网络接口信息
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        for interface_name, addresses in addrs.items():
            # 获取接口状态
            interface_stats = stats.get(interface_name, None)
            is_up = interface_stats.isup if interface_stats else False

            # 获取IP地址信息
            ip_address = ""
            netmask = ""
            broadcast = ""
            mac_address = ""

            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    ip_address = addr.address
                    netmask = addr.netmask
                    broadcast = addr.broadcast
                elif addr.family == psutil.AF_LINK:  # MAC地址
                    mac_address = addr.address

            # 获取网络IO统计
            interface_io = io_counters.get(interface_name, None)

            interface_info = NetworkInterfaceInfo(
                name=interface_name,
                ip_address=ip_address,
                netmask=netmask,
                broadcast=broadcast,
                mac_address=mac_address,
                is_up=is_up,
                bytes_sent=interface_io.bytes_sent if interface_io else 0,
                bytes_recv=interface_io.bytes_recv if interface_io else 0,
                packets_sent=interface_io.packets_sent if interface_io else 0,
                packets_recv=interface_io.packets_recv if interface_io else 0
            )
            interfaces.append(interface_info)

        return interfaces

    def _get_docker_info(self) -> DockerInfo:
        """获取Docker信息"""
        if not self.docker_client:
            return DockerInfo(
                version="",
                api_version="",
                containers_total=0,
                containers_running=0,
                containers_stopped=0,
                containers_paused=0,
                images_total=0,
                images_size=0,
                volumes_total=0,
                networks_total=0,
                is_docker_available=False,
                docker_root_dir=""
            )

        try:
            # 获取Docker版本信息
            version_info = self.docker_client.version()

            # 获取容器信息
            containers = self.docker_client.containers.list(all=True)
            containers_running = len([c for c in containers if c.status == 'running'])
            containers_stopped = len([c for c in containers if c.status == 'exited' or c.status == 'stopped'])
            containers_paused = len([c for c in containers if c.status == 'paused'])

            # 获取镜像信息
            images = self.docker_client.images.list()
            images_size = sum(img.attrs['Size'] for img in images)

            # 获取卷信息
            volumes = self.docker_client.volumes.list()

            # 获取网络信息
            networks = self.docker_client.networks.list()

            # 获取Docker根目录（需要info接口）
            info = self.docker_client.info()
            docker_root_dir = info.get('DockerRootDir', '')

            return DockerInfo(
                version=version_info.get('Version', ''),
                api_version=version_info.get('ApiVersion', ''),
                containers_total=len(containers),
                containers_running=containers_running,
                containers_stopped=containers_stopped,
                containers_paused=containers_paused,
                images_total=len(images),
                images_size=images_size,
                volumes_total=len(volumes),
                networks_total=len(networks),
                is_docker_available=True,
                docker_root_dir=docker_root_dir
            )
        except Exception as e:
            logger.error(f"获取Docker信息失败: {e}")
            return DockerInfo(
                version="",
                api_version="",
                containers_total=0,
                containers_running=0,
                containers_stopped=0,
                containers_paused=0,
                images_total=0,
                images_size=0,
                volumes_total=0,
                networks_total=0,
                is_docker_available=False,
                docker_root_dir=""
            )

    def _get_top_processes(self, limit: int = 10) -> List[ProcessInfo]:
        """获取消耗资源最多的进程"""
        processes = []

        # 获取所有进程信息
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent',
                                         'memory_percent', 'memory_info', 'create_time',
                                         'cmdline']):
            try:
                process_info = proc.info

                # 获取内存使用信息
                memory_info = process_info.get('memory_info', None)

                process = ProcessInfo(
                    pid=process_info['pid'],
                    name=process_info['name'],
                    status=process_info['status'],
                    cpu_percent=process_info.get('cpu_percent', 0),
                    memory_percent=process_info.get('memory_percent', 0),
                    memory_rss=memory_info.rss if memory_info else 0,
                    memory_vms=memory_info.vms if memory_info else 0,
                    create_time=process_info['create_time'],
                    cmdline=process_info.get('cmdline', [])
                )
                processes.append(process)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # 按CPU使用率排序
        processes.sort(key=lambda x: x.cpu_percent, reverse=True)

        # 限制返回数量
        return processes[:limit]

class ConfigManager:
    """配置管理器"""

    @staticmethod
    def load_config(config_file: str) -> Dict:
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            # 设置默认值
            defaults = {
                'port': 11187,
                'host': '0.0.0.0',
                'api_prefix': '/api',
                'token': 'default_token_change_me',
                'daemon': False,
                'log_dir': './logs',
                'log_level': 'INFO',
                'compose_root': './services',
                'docker_compose_bin': 'docker-compose',
                'docker_bin': 'docker',
                'docker_socket': 'unix:///var/run/docker.sock',
                'max_upload_size': 100 * 1024 * 1024,  # 100MB
                'database_file': './docker_manager.db',
                'static_dir': './static',  # 静态文件目录
                'static_index_file': 'index.html',  # 默认索引文件
                'agent_service_report_enabled': True,
                'agent_service_report_interval_sec': 30,
                'platform_agent_url': 'http://secflow-platform-agent.sothothv2-ns.svc.cluster.local',
                'platform_agent_report_timeout_sec': 15,
                'agent_key': '',
                'docker_compose_pull_timeout_sec': 1800,
                'docker_compose_up_timeout_sec': 1200,
                'service_status_timeout_sec': 8,
                'services_cache_ttl_sec': 5
            }

            # 更新配置
            for key, value in defaults.items():
                if key not in config_data:
                    config_data[key] = value

            return config_data
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            sys.exit(1)

class DatabaseManager:
    """数据库管理器"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """初始化数据库"""
        global db_conn
        db_conn = sqlite3.connect(self.db_path, check_same_thread=False)
        db_conn.row_factory = sqlite3.Row

        # 创建服务表
        cursor = db_conn.cursor()
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS services (
                                                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                               name TEXT UNIQUE NOT NULL,
                                                               path TEXT NOT NULL,
                                                               project_name TEXT,
                                                               template_id INTEGER,
                                                               template_name TEXT,
                                                               tags_json TEXT DEFAULT '[]',
                                                               enabled INTEGER DEFAULT 1,
                                                               status TEXT DEFAULT 'stopped',
                                                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                       ''')

        cursor.execute("PRAGMA table_info(services)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        if 'project_name' not in existing_columns:
            cursor.execute("ALTER TABLE services ADD COLUMN project_name TEXT")
        if 'template_id' not in existing_columns:
            cursor.execute("ALTER TABLE services ADD COLUMN template_id INTEGER")
        if 'template_name' not in existing_columns:
            cursor.execute("ALTER TABLE services ADD COLUMN template_name TEXT")
        if 'tags_json' not in existing_columns:
            cursor.execute("ALTER TABLE services ADD COLUMN tags_json TEXT DEFAULT '[]'")

        # 创建配置表
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS config (
                                                             key TEXT PRIMARY KEY,
                                                             value TEXT,
                                                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                       ''')

        db_conn.commit()

    def get_connection(self):
        """获取数据库连接"""
        return db_conn

    def execute_query(self, query: str, params: tuple = ()):
        """执行查询"""
        cursor = db_conn.cursor()
        cursor.execute(query, params)
        db_conn.commit()
        return cursor

    def fetch_one(self, query: str, params: tuple = ()):
        """获取单条记录"""
        cursor = db_conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    def fetch_all(self, query: str, params: tuple = ()):
        """获取所有记录"""
        cursor = db_conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

class ServiceManager:
    """服务管理器"""

    def __init__(self, config: Dict):
        self.config = config
        self.compose_root = Path(config['compose_root'])
        self.docker_compose_bin = config['docker_compose_bin']
        self.docker_bin = config.get('docker_bin', 'docker')
        self.docker_socket = config['docker_socket']  # 保存docker_socket
        self.pull_timeout_sec = int(config.get('docker_compose_pull_timeout_sec', 300))
        self.up_timeout_sec = int(config.get('docker_compose_up_timeout_sec', 1200))
        self.status_timeout_sec = max(1, int(config.get('service_status_timeout_sec', 8)))
        self.db = DatabaseManager(config['database_file'])
        self.runtime_operations: Dict[str, Dict[str, Any]] = {}
        self.runtime_operations_lock = threading.Lock()

        # 创建服务目录
        self.compose_root.mkdir(parents=True, exist_ok=True)
        self.backfill_service_project_names()

    def _get_runtime_operation(self, service_name: str) -> Dict[str, Any]:
        with self.runtime_operations_lock:
            data = self.runtime_operations.get(service_name, {}).copy()
        if not data:
            return {
                'active': False,
                'phase': 'idle',
                'progress': 0,
                'message': '',
                'updated_at': datetime.now().isoformat()
            }
        return data

    def _set_runtime_operation(
        self,
        service_name: str,
        phase: str,
        progress: int = 0,
        message: str = '',
        active: bool = True,
        error: str = '',
        detail: Optional[Dict[str, Any]] = None
    ):
        payload = {
            'active': bool(active),
            'phase': phase,
            'progress': max(0, min(100, int(progress))),
            'message': message,
            'error': error,
            'updated_at': datetime.now().isoformat(),
            'detail': detail or {}
        }
        with self.runtime_operations_lock:
            self.runtime_operations[service_name] = payload

    def backfill_service_project_names(self):
        """为历史服务补齐持久化的 compose project 名称。"""
        try:
            rows = self.db.fetch_all(
                "SELECT name, path, project_name FROM services"
            )
            for row in rows or []:
                current_project = str(row['project_name'] or '').strip()
                if current_project:
                    continue
                service_name = str(row['name'])
                compose_file = self.get_compose_file(service_name)
                resolved_project = self.resolve_compose_project_name(compose_file, service_name)
                self.db.execute_query(
                    "UPDATE services SET project_name = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (resolved_project, service_name)
                )
        except Exception as e:
            logger.warning(f"补齐 services.project_name 失败: {e}")

    def get_service_operation_status(self, service_name: str) -> Dict[str, Any]:
        return self._get_runtime_operation(service_name)

    @staticmethod
    def normalize_tags(tags: Any) -> List[str]:
        if isinstance(tags, str):
            try:
                parsed = json.loads(tags)
                if isinstance(parsed, list):
                    tags = parsed
                else:
                    tags = [item.strip() for item in tags.split(',')]
            except Exception:
                tags = [item.strip() for item in tags.split(',')]
        elif not isinstance(tags, (list, tuple, set)):
            tags = []

        seen = set()
        normalized: List[str] = []
        for item in tags:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    def get_service_tags(self, service_name: str) -> List[str]:
        row = self.db.fetch_one("SELECT tags_json FROM services WHERE name = ?", (service_name,))
        if not row:
            return []
        raw = row['tags_json'] if isinstance(row, sqlite3.Row) else row.get('tags_json')
        return self.normalize_tags(raw)

    def _run_pull_with_progress(self, service_name: str, compose_file: Path, project_name: str) -> Tuple[bool, str]:
        """
        执行 docker compose pull 并尽可能解析进度。
        注：docker compose pull 在非TTY环境下进度信息有限，这里做“最佳努力”解析。
        """
        compose_data = self.parse_compose_file(compose_file) or {}
        declared_services = compose_data.get('services') or {}
        total_services = max(len(declared_services), 1)
        completed_services = 0
        seen_completed = set()

        self._set_runtime_operation(
            service_name,
            phase='pulling',
            progress=5,
            message='开始拉取镜像',
            active=True,
            detail={'total_services': total_services, 'completed_services': 0}
        )

        cmd = [
            self.docker_compose_bin,
            '-f', str(compose_file),
            '-p', project_name,
            'pull'
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=self.get_env_with_docker_host(),
            bufsize=1
        )

        lines: List[str] = []
        start_time = time.time()

        while True:
            if process.stdout is None:
                break
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                # 超时保护
                if (time.time() - start_time) > self.pull_timeout_sec:
                    process.kill()
                    return False, f"pull超时({self.pull_timeout_sec}s)"
                continue

            line = line.rstrip('\n')
            lines.append(line)
            line_lower = line.lower()

            # 解析服务级完成事件（Pulled / Image is up to date / Already exists）
            # 常见格式： "<service> Pulled"
            tokens = line.split()
            if len(tokens) >= 2:
                svc_candidate = tokens[0]
                if (
                    (' pulled' in line_lower)
                    or ('up to date' in line_lower)
                    or ('already exists' in line_lower)
                ):
                    if svc_candidate not in seen_completed:
                        seen_completed.add(svc_candidate)
                        completed_services += 1

            progress = 5 + int(min(completed_services, total_services) * 75 / total_services)
            self._set_runtime_operation(
                service_name,
                phase='pulling',
                progress=progress,
                message=line[-300:],
                active=True,
                detail={
                    'total_services': total_services,
                    'completed_services': min(completed_services, total_services),
                    'last_output_line': line
                }
            )

        rc = process.wait(timeout=5)
        if rc == 0:
            self._set_runtime_operation(
                service_name,
                phase='pulling',
                progress=80,
                message='镜像拉取完成',
                active=True,
                detail={'total_services': total_services, 'completed_services': min(completed_services, total_services)}
            )
            return True, "镜像拉取完成"

        tail = '\n'.join(lines[-20:]).strip()
        err_msg = tail or 'docker compose pull 执行失败'
        self._set_runtime_operation(
            service_name,
            phase='failed',
            progress=max(1, self._get_runtime_operation(service_name).get('progress', 1)),
            message='镜像拉取失败',
            active=False,
            error=err_msg
        )
        return False, err_msg

    def get_env_with_docker_host(self):
        """获取包含DOCKER_HOST环境变量的环境变量字典"""
        env = os.environ.copy()
        env['DOCKER_HOST'] = self.docker_socket
        return env

    def validate_compose_file(self, compose_file: Path) -> Tuple[bool, str]:
        """验证docker-compose文件是否有效"""
        try:
            # 检查文件是否存在
            if not compose_file.exists():
                return False, f"文件不存在: {compose_file}"

            # 读取并解析YAML
            with open(compose_file, 'r', encoding='utf-8') as f:
                yaml_content = f.read()

            parsed = yaml.safe_load(yaml_content)

            # 基础校验：必须包含services部分
            if not parsed:
                return False, "YAML文件为空"

            # 检查是否是有效的docker-compose文件
            # 允许顶层的name字段（docker-compose v3.4+支持）
            if 'services' not in parsed:
                return False, "YAML文件必须包含'services'部分"

            # 验证services部分
            services = parsed.get('services', {})
            if not services:
                return False, "services部分不能为空"

            # 检查每个服务的基本结构
            for service_name, service_config in services.items():
                if not isinstance(service_config, dict):
                    return False, f"服务 '{service_name}' 配置必须是字典格式"

                # 检查必要字段
                if 'image' not in service_config and 'build' not in service_config:
                    return False, f"服务 '{service_name}' 必须包含'image'或'build'字段"

            # 尝试使用docker-compose config验证（可选，更严格）
            try:
                cmd = [
                    self.docker_compose_bin,
                    '-f', str(compose_file),
                    'config'
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=self.get_env_with_docker_host(),
                    timeout=10
                )

                if result.returncode != 0:
                    return False, f"docker-compose验证失败: {result.stderr}"

            except subprocess.TimeoutExpired:
                # 超时不是致命错误，继续
                logger.warning(f"docker-compose验证超时，跳过")
            except Exception as e:
                # 其他错误不是致命错误，继续
                logger.warning(f"docker-compose验证出错: {e}")

            return True, "验证成功"

        except yaml.YAMLError as e:
            return False, f"YAML格式错误: {e}"
        except Exception as e:
            return False, f"验证失败: {str(e)}"

    def _extract_declared_container_names(self, compose_file: Path) -> List[str]:
        """提取compose里显式声明的container_name。"""
        try:
            with open(compose_file, 'r', encoding='utf-8') as f:
                parsed = yaml.safe_load(f.read()) or {}
            services = parsed.get('services') or {}
            names: List[str] = []
            for _, cfg in services.items():
                if not isinstance(cfg, dict):
                    continue
                cname = cfg.get('container_name')
                if isinstance(cname, str) and cname.strip():
                    names.append(cname.strip())
            return names
        except Exception:
            return []

    def _find_container_name_conflicts(self, container_names: List[str]) -> List[str]:
        """检查container_name是否与现有容器重名。"""
        if not container_names:
            return []
        try:
            result = subprocess.run(
                [self.docker_bin, 'ps', '-a', '--format', '{{.Names}}'],
                capture_output=True,
                text=True,
                env=self.get_env_with_docker_host(),
                timeout=10
            )
            if result.returncode != 0:
                logger.warning(f"检查容器重名失败: {result.stderr}")
                return []
            existing = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            conflicts = [name for name in container_names if name in existing]
            return conflicts
        except Exception as e:
            logger.warning(f"检查容器重名异常: {e}")
            return []

    def get_file_type(self, file_path: Path) -> str:
        """获取文件类型"""
        if file_path.is_dir():
            return 'directory'

        # 检查常见文件类型
        ext = file_path.suffix.lower()
        if ext in ['.yaml', '.yml']:
            return 'yaml'
        elif ext in ['.json']:
            return 'json'
        elif ext in ['.py']:
            return 'python'
        elif ext in ['.sh']:
            return 'shell'
        elif ext in ['.md', '.txt']:
            return 'text'
        elif ext in ['.html', '.htm']:
            return 'html'
        elif ext in ['.css']:
            return 'css'
        elif ext in ['.js']:
            return 'javascript'
        elif ext in ['.xml']:
            return 'xml'
        elif ext in ['.sql']:
            return 'sql'
        else:
            return 'binary'
    def get_service_directory_structure(self, service_name: str) -> Dict[str, Any]:
        """获取服务文件夹结构"""
        try:
            service_path = self.get_service_path(service_name)

            if not service_path.exists():
                return {'error': f'服务 {service_name} 不存在'}

            result = {
                'service_name': service_name,
                'path': str(service_path),
                'structure': self._scan_directory(service_path)
            }

            return result
        except Exception as e:
            logger.error(f"获取服务文件夹结构失败: {e}")
            return {'error': str(e)}

    def _scan_directory(self, path: Path, depth: int = 0, max_depth: int = 10) -> Dict[str, Any]:
        """递归扫描目录结构"""
        if depth > max_depth:
            return {'name': path.name, 'type': 'directory', 'error': '深度限制'}

        try:
            result = {
                'name': path.name,
                'path': str(path),
                'type': 'directory',
                'modified': datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                'children': []
            }

            # 遍历目录内容
            for item in sorted(path.iterdir()):
                if item.is_dir():
                    result['children'].append(self._scan_directory(item, depth + 1, max_depth))
                else:
                    file_info = {
                        'name': item.name,
                        'path': str(item),
                        'type': 'file',
                        'size': item.stat().st_size,
                        'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat(),
                        'extension': item.suffix.lower()
                    }
                    result['children'].append(file_info)

            return result
        except Exception as e:
            return {'name': path.name, 'type': 'directory', 'error': str(e)}

    def get_service_file(self, service_name: str, file_path: str) -> Tuple[bool, str, bytes]:
        """获取服务文件内容"""
        try:
            service_path = self.get_service_path(service_name)

            if not service_path.exists():
                return False, f"服务 {service_name} 不存在", b""

            # 构建完整路径并安全检查
            target_path = (service_path / file_path).resolve()

            # 检查是否在服务目录内
            if not str(target_path).startswith(str(service_path.resolve())):
                return False, "非法文件路径", b""

            if not target_path.exists():
                return False, f"文件不存在: {file_path}", b""

            if not target_path.is_file():
                return False, f"不是文件: {file_path}", b""

            # 读取文件内容
            with open(target_path, 'rb') as f:
                content = f.read()

            return True, "成功", content

        except Exception as e:
            logger.error(f"获取服务文件失败: {e}")
            return False, str(e), b""

    def update_service_file(self, service_name: str, file_path: str, content: bytes) -> Tuple[bool, str]:
        """更新服务文件内容"""
        try:
            service_path = self.get_service_path(service_name)

            if not service_path.exists():
                return False, f"服务 {service_name} 不存在"

            # 构建完整路径并安全检查
            target_path = (service_path / file_path).resolve()

            # 检查是否在服务目录内
            if not str(target_path).startswith(str(service_path.resolve())):
                return False, "非法文件路径"

            # 确保目录存在
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # 备份原文件（如果存在）
            if target_path.exists():
                backup_path = target_path.with_suffix(f"{target_path.suffix}.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}")
                shutil.copy2(target_path, backup_path)
                logger.info(f"备份文件: {backup_path}")

            # 写入新内容
            with open(target_path, 'wb') as f:
                f.write(content)

            # 如果是docker-compose文件，验证格式
            if target_path.name in ['docker-compose.yaml', 'docker-compose.yml', 'compose.yaml', 'compose.yml']:
                is_valid, error_msg = self.validate_compose_file(target_path)
                if not is_valid:
                    # 恢复备份
                    if target_path.exists() and backup_path and backup_path.exists():
                        shutil.copy2(backup_path, target_path)
                    return False, f"YAML验证失败: {error_msg}"

            logger.info(f"更新服务文件成功: {target_path}")
            return True, "文件更新成功"

        except Exception as e:
            logger.error(f"更新服务文件失败: {e}")
            return False, str(e)

    def get_service_path(self, service_name: str) -> Path:
        """获取服务路径"""
        return self.compose_root / service_name

    def get_compose_file(self, service_name: str) -> Path:
        """获取compose文件路径"""
        return self.get_service_path(service_name) / 'docker-compose.yaml'

    def get_project_name(self, service_name: str) -> str:
        """获取 docker compose project 名称。

        优先读取数据库中部署时记录的 project_name。
        历史数据如果缺失，则从 compose 顶层 `name` 自动补齐并回写数据库。
        最后才回退到服务名（目录名）。
        """
        record = self.db.fetch_one(
            "SELECT project_name FROM services WHERE name = ?",
            (service_name,)
        )
        if record:
            project_name = str(record['project_name'] or '').strip()
            if project_name:
                return project_name

        compose_file = self.get_compose_file(service_name)
        compose_data = self.parse_compose_file(compose_file)
        if isinstance(compose_data, dict):
            project_name = str(compose_data.get('name') or '').strip()
            if project_name:
                try:
                    self.db.execute_query(
                        "UPDATE services SET project_name = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                        (project_name, service_name)
                    )
                except Exception as e:
                    logger.warning(f"回写服务 {service_name} 的 project_name 失败: {e}")
                return project_name
        return service_name

    def resolve_compose_project_name(self, compose_file: Path, service_name: str) -> str:
        """在服务创建/导入时解析并固定 compose project 名称。"""
        compose_data = self.parse_compose_file(compose_file)
        if isinstance(compose_data, dict):
            project_name = str(compose_data.get('name') or '').strip()
            if project_name:
                return project_name
        return service_name

    def parse_compose_file(self, compose_file: Path) -> Dict:
        """解析compose文件"""
        try:
            with open(compose_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"解析compose文件失败: {e}")
            return {}

    def get_service_status(self, service_name: str) -> Dict:
        """获取服务状态"""
        try:
            compose_file = self.get_compose_file(service_name)
            operation = self.get_service_operation_status(service_name)
            if not compose_file.exists():
                return {'status': 'not_found', 'containers': [], 'operation': operation}

            project_name = self.get_project_name(service_name)

            # 方法1：使用JSON Lines格式输出（每行一个JSON对象）
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'ps',
                '--format', 'json'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self.get_env_with_docker_host(),
                timeout=self.status_timeout_sec
            )

            if result.returncode == 0:
                containers = []
                output = result.stdout.strip()

                # 处理 JSON Lines / JSON 数组 / 单对象三种输出格式
                if output:
                    for line in output.splitlines():
                        stripped = line.strip()
                        if not stripped:
                            continue
                        try:
                            parsed = json.loads(stripped)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(parsed, dict):
                            containers.append(parsed)
                        elif isinstance(parsed, list):
                            containers.extend([item for item in parsed if isinstance(item, dict)])

                    if not containers:
                        try:
                            parsed = json.loads(output)
                            if isinstance(parsed, dict):
                                containers = [parsed]
                            elif isinstance(parsed, list):
                                containers = [item for item in parsed if isinstance(item, dict)]
                        except Exception:
                            containers = []

                running_count = sum(1 for c in containers if c.get('State') == 'running')
                total_count = len(containers)

                status = 'running' if running_count == total_count > 0 else 'partially_running'
                if total_count == 0:
                    status = 'stopped'

                if operation.get('active'):
                    status = str(operation.get('phase') or status)

                return {
                    'status': status,
                    'containers': containers,
                    'running': running_count,
                    'total': total_count,
                    'operation': operation
                }
            else:
                # 命令执行失败，检查是否是服务未运行
                if "no such service" in result.stderr.lower() or "no configuration" in result.stderr.lower():
                    fallback_status = 'stopped'
                else:
                    fallback_status = 'unknown'
                if operation.get('active'):
                    fallback_status = str(operation.get('phase') or fallback_status)
                return {'status': fallback_status, 'containers': [], 'operation': operation}

        except subprocess.TimeoutExpired:
            operation = self.get_service_operation_status(service_name)
            status = 'unknown'
            if operation.get('active'):
                status = str(operation.get('phase') or status)
            return {
                'status': status,
                'containers': [],
                'operation': operation,
                'error': f'compose ps timeout ({self.status_timeout_sec}s)'
            }
        except Exception as e:
            logger.error(f"获取服务状态失败: {e}")
            operation = self.get_service_operation_status(service_name)
            status = 'error'
            if operation.get('active'):
                status = str(operation.get('phase') or status)
            return {'status': status, 'error': str(e), 'operation': operation}

    def start_service(self, service_name: str) -> Tuple[bool, str]:
        """启动服务"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            self._set_runtime_operation(service_name, 'starting', 1, '准备启动服务', active=True)

            # 检查服务状态
            status_info = self.get_service_status(service_name)
            if status_info['status'] == 'running':
                self._set_runtime_operation(service_name, 'running', 100, '服务已在运行', active=False)
                return True, "服务已在运行"

            project_name = self.get_project_name(service_name)

            # 执行docker-compose pull（带进度）
            pull_ok, pull_msg = self._run_pull_with_progress(service_name, compose_file, project_name)
            if not pull_ok:
                self.db.execute_query(
                    "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                return False, f"拉取镜像失败: {pull_msg}"

            # 执行docker-compose up -d
            self._set_runtime_operation(service_name, 'starting', 85, '镜像拉取完成，启动容器中', active=True)
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'up',
                '-d',
                '--remove-orphans'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self.get_env_with_docker_host(),
                timeout=self.up_timeout_sec
            )

            if result.returncode == 0:
                # 更新数据库状态
                self.db.execute_query(
                    "UPDATE services SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                self._set_runtime_operation(service_name, 'running', 100, '服务启动成功', active=False)
                return True, "服务启动成功"
            else:
                detail = (result.stderr or result.stdout or '').strip()
                self.db.execute_query(
                    "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                self._set_runtime_operation(service_name, 'failed', 95, '服务启动失败', active=False, error=detail)
                return False, f"启动失败: {detail}"

        except subprocess.TimeoutExpired as e:
            cmd = ' '.join(e.cmd) if isinstance(e.cmd, list) else str(e.cmd)
            timeout_sec = int(e.timeout or 0)
            self.db.execute_query(
                "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (service_name,)
            )
            self._set_runtime_operation(service_name, 'failed', 95, f"启动超时({timeout_sec}s)", active=False, error=cmd)
            return False, f"启动超时({timeout_sec}s): {cmd}"

        except Exception as e:
            logger.error(f"启动服务失败: {e}")
            self.db.execute_query(
                "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (service_name,)
            )
            self._set_runtime_operation(service_name, 'failed', 95, '启动失败', active=False, error=str(e))
            return False, f"启动失败: {str(e)}"

    def stop_service(self, service_name: str) -> Tuple[bool, str]:
        """停止服务"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            self._set_runtime_operation(service_name, 'stopping', 10, '正在停止服务', active=True)

            project_name = self.get_project_name(service_name)

            # 执行docker-compose down
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'down'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self.get_env_with_docker_host()
            )

            if result.returncode == 0:
                # 更新数据库状态
                self.db.execute_query(
                    "UPDATE services SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                self._set_runtime_operation(service_name, 'stopped', 100, '服务停止成功', active=False)
                return True, "服务停止成功"
            else:
                detail = (result.stderr or result.stdout or '').strip()
                self._set_runtime_operation(service_name, 'failed', 95, '服务停止失败', active=False, error=detail)
                return False, f"停止失败: {detail}"

        except Exception as e:
            logger.error(f"停止服务失败: {e}")
            self._set_runtime_operation(service_name, 'failed', 95, '停止失败', active=False, error=str(e))
            return False, f"停止失败: {str(e)}"

    def restart_service(self, service_name: str) -> Tuple[bool, str]:
        """重启服务"""
        self._set_runtime_operation(service_name, 'restarting', 1, '准备重启服务', active=True)
        success, message = self.stop_service(service_name)
        if success:
            time.sleep(2)  # 等待2秒
            return self.start_service(service_name)
        self._set_runtime_operation(service_name, 'failed', 95, '重启失败', active=False, error=message)
        return False, message

    def update_service(self, service_name: str) -> Tuple[bool, str]:
        """更新服务镜像并重启（任意状态可调用）"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            self._set_runtime_operation(service_name, 'updating', 1, '准备更新镜像并重启', active=True)

            # 更新语义固定为 pull + restart，确保容器实际重建生效。
            project_name = self.get_project_name(service_name)
            pull_ok, pull_msg = self._run_pull_with_progress(service_name, compose_file, project_name)
            if not pull_ok:
                self.db.execute_query(
                    "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                self._set_runtime_operation(service_name, 'failed', 95, '更新失败', active=False, error=pull_msg)
                return False, f"拉取镜像失败: {pull_msg}"

            self._set_runtime_operation(service_name, 'restarting', 85, '镜像拉取完成，重启服务中', active=True)
            restart_ok, restart_msg = self.restart_service(service_name)
            if restart_ok:
                return True, "服务更新成功"
            return False, f"服务更新失败: {restart_msg}"
        except Exception as e:
            logger.error(f"更新服务失败: {e}")
            self.db.execute_query(
                "UPDATE services SET status = 'error', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (service_name,)
            )
            self._set_runtime_operation(service_name, 'failed', 95, '更新失败', active=False, error=str(e))
            return False, f"更新失败: {str(e)}"

    def create_service_from_yaml(
        self,
        service_name: str,
        yaml_content: str,
        template_name: str = '',
        template_id: Optional[int] = None,
        tags: Optional[List[str]] = None,
        files: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        """从YAML创建服务"""
        service_path = None
        try:
            # 验证服务名称
            if not service_name or not re.match(r'^[a-zA-Z0-9_-]+$', service_name):
                return False, "服务名称只能包含字母、数字、下划线和连字符"

            # 检查服务是否已存在
            existing = self.db.fetch_one("SELECT id FROM services WHERE name = ?", (service_name,))
            if existing:
                return False, f"服务 {service_name} 已存在"

            # 创建服务目录
            service_path = self.get_service_path(service_name)
            service_path.mkdir(parents=True, exist_ok=False)

            # 保存YAML文件
            compose_file = service_path / 'docker-compose.yaml'
            with open(compose_file, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            # 写入随YAML下发的附加文件（例如 .llm-provider-files/*）
            for item in (files or []):
                if not isinstance(item, dict):
                    continue
                rel = str(item.get('relative_path') or '').strip()
                content = item.get('content')
                if not rel or not isinstance(content, str):
                    continue
                rel_path = Path(rel)
                if rel_path.is_absolute() or '..' in rel_path.parts:
                    shutil.rmtree(service_path, ignore_errors=True)
                    return False, f"附加文件路径非法: {rel}"
                target_file = (service_path / rel_path).resolve()
                try:
                    target_file.relative_to(service_path.resolve())
                except Exception:
                    shutil.rmtree(service_path, ignore_errors=True)
                    return False, f"附加文件路径越界: {rel}"
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding='utf-8')

            # 验证YAML格式和docker-compose有效性
            is_valid, error_msg = self.validate_compose_file(compose_file)
            if not is_valid:
                shutil.rmtree(service_path)
                return False, f"YAML文件验证失败: {error_msg}"

            # 预检查：避免container_name与已有容器冲突，导致“创建成功但启动失败”
            declared_names = self._extract_declared_container_names(compose_file)
            conflicts = self._find_container_name_conflicts(declared_names)
            if conflicts:
                shutil.rmtree(service_path, ignore_errors=True)
                return False, f"container_name冲突: {', '.join(conflicts)}，请修改模板中的container_name后重试"

            project_name = self.resolve_compose_project_name(compose_file, service_name)

            # 插入数据库记录
            self.db.execute_query(
                "INSERT INTO services (name, path, project_name, template_id, template_name, tags_json, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'stopped')",
                (
                    service_name,
                    str(service_path),
                    project_name,
                    template_id,
                    str(template_name or '').strip(),
                    json.dumps(self.normalize_tags(tags), ensure_ascii=False),
                )
            )

            logger.info(f"服务 {service_name} 创建成功")
            return True, "服务创建成功"

        except yaml.YAMLError as e:
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"YAML格式错误: {e}"
        except Exception as e:
            logger.error(f"创建服务失败: {e}")
            # 清理已创建的目录
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"创建失败: {str(e)}"

    def create_service_from_zip(
        self,
        service_name: str,
        zip_file_path: str,
        template_name: str = '',
        template_id: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """从压缩包创建服务（支持多种格式）"""
        temp_dir = None
        service_path = None

        # 支持的压缩格式
        SUPPORTED_FORMATS = [
            '.zip', '.tar', '.tar.gz', '.tgz',
            '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz'
        ]

        try:
            # 验证服务名称
            if not service_name or not re.match(r'^[a-zA-Z0-9_-]+$', service_name):
                return False, "服务名称只能包含字母、数字、下划线和连字符"

            # 检查服务是否已存在
            existing = self.db.fetch_one("SELECT id FROM services WHERE name = ?", (service_name,))
            if existing:
                return False, f"服务 {service_name} 已存在"

            # 检查文件是否存在
            archive_path = Path(zip_file_path)
            if not archive_path.exists():
                return False, f"压缩包文件不存在: {zip_file_path}"

            # 获取文件扩展名并检查是否支持
            file_ext = None
            for ext in SUPPORTED_FORMATS:
                if str(archive_path).lower().endswith(ext):
                    file_ext = ext
                    break

            if not file_ext:
                # 如果没有找到匹配的扩展名，尝试通过文件头检测
                file_ext = self._detect_archive_format(zip_file_path)
                if not file_ext:
                    supported_list = ', '.join(SUPPORTED_FORMATS)
                    return False, f"不支持的压缩格式。支持的格式: {supported_list}"

            # 创建临时目录解压文件
            temp_dir = tempfile.mkdtemp(prefix=f"docker_service_{service_name}_")
            logger.info(f"解压文件到临时目录: {temp_dir}, 格式: {file_ext}")

            # 解压文件
            success, extract_msg = self._extract_archive(zip_file_path, temp_dir, file_ext)

            if not success:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, f"解压失败: {extract_msg}"

            # 查找docker-compose.yaml文件
            yaml_files = []
            for pattern in ['docker-compose.yaml', 'docker-compose.yml', 'compose.yaml', 'compose.yml']:
                yaml_files.extend(list(Path(temp_dir).rglob(pattern)))

            if not yaml_files:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, "未找到docker-compose配置文件"

            # 使用第一个找到的YAML文件
            source_yaml = yaml_files[0]

            # 验证YAML文件
            is_valid, error_msg = self.validate_compose_file(source_yaml)
            if not is_valid:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, f"YAML文件验证失败: {error_msg}"

            # 创建服务目录
            service_path = self.get_service_path(service_name)
            service_path.mkdir(parents=True, exist_ok=False)

            # 复制所有文件到服务目录
            logger.info(f"复制文件到服务目录: {service_path}")
            for item in Path(temp_dir).iterdir():
                dest = service_path / item.name
                if item.is_dir():
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

            # 确保docker-compose.yaml文件存在（如果原文件名不是docker-compose.yaml）
            target_yaml = service_path / 'docker-compose.yaml'
            if not target_yaml.exists():
                # 如果源文件是其他名称，重命名为docker-compose.yaml
                if source_yaml.name in ['docker-compose.yml', 'compose.yaml', 'compose.yml']:
                    shutil.copy2(source_yaml, target_yaml)
                    # 删除原文件
                    (service_path / source_yaml.name).unlink(missing_ok=True)

            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
            temp_dir = None

            # 再次验证目标文件
            is_valid, error_msg = self.validate_compose_file(target_yaml)
            if not is_valid:
                shutil.rmtree(service_path, ignore_errors=True)
                return False, f"YAML文件验证失败: {error_msg}"

            # 预检查：避免container_name与已有容器冲突
            declared_names = self._extract_declared_container_names(target_yaml)
            conflicts = self._find_container_name_conflicts(declared_names)
            if conflicts:
                shutil.rmtree(service_path, ignore_errors=True)
                return False, f"container_name冲突: {', '.join(conflicts)}，请修改模板中的container_name后重试"

            project_name = self.resolve_compose_project_name(target_yaml, service_name)

            # 插入数据库记录
            self.db.execute_query(
                "INSERT INTO services (name, path, project_name, template_id, template_name, tags_json, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'stopped')",
                (
                    service_name,
                    str(service_path),
                    project_name,
                    template_id,
                    str(template_name or '').strip(),
                    json.dumps(self.normalize_tags(tags), ensure_ascii=False),
                )
            )

            logger.info(f"服务 {service_name} 从压缩包创建成功，格式: {file_ext}")
            return True, f"服务创建成功 (格式: {file_ext})"

        except zipfile.BadZipFile:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, "无效的ZIP文件"
        except tarfile.ReadError as e:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"压缩文件读取失败: {str(e)}"
        except yaml.YAMLError as e:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"YAML格式错误: {e}"
        except Exception as e:
            logger.error(f"从压缩包创建服务失败: {e}")
            # 清理
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            if service_path and service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"创建失败: {str(e)}"

    def _extract_archive(self, archive_path: str, extract_dir: str, file_ext: str) -> Tuple[bool, str]:
        """解压压缩文件"""
        try:
            if file_ext in ['.zip']:
                # 解压ZIP文件
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                return True, "ZIP解压成功"

            elif file_ext in ['.tar']:
                # 解压TAR文件
                with tarfile.open(archive_path, 'r') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True, "TAR解压成功"

            elif file_ext in ['.tar.gz', '.tgz']:
                # 解压TAR.GZ文件
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True, "TAR.GZ解压成功"

            elif file_ext in ['.tar.bz2', '.tbz', '.tbz2']:
                # 解压TAR.BZ2文件
                with tarfile.open(archive_path, 'r:bz2') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True, "TAR.BZ2解压成功"

            elif file_ext in ['.tar.xz', '.txz']:
                # 解压TAR.XZ文件
                with tarfile.open(archive_path, 'r:xz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return True, "TAR.XZ解压成功"

            else:
                return False, f"不支持的压缩格式: {file_ext}"

        except Exception as e:
            return False, f"解压失败: {str(e)}"

    def _detect_archive_format(self, file_path: str) -> str:
        """通过文件头检测压缩格式"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(261)  # 读取足够多的字节来识别各种格式

            # ZIP文件头
            if header.startswith(b'PK\x03\x04'):
                return '.zip'

            # TAR文件头
            if header[257:262] == b'ustar':
                return '.tar'

            # GZIP文件头
            if header[:2] == b'\x1f\x8b':
                # 检查是否是tar.gz
                try:
                    with tarfile.open(file_path, 'r:gz') as tf:
                        return '.tar.gz'
                except:
                    return '.gz'

            # BZIP2文件头
            if header[:3] == b'BZh':
                # 检查是否是tar.bz2
                try:
                    with tarfile.open(file_path, 'r:bz2') as tf:
                        return '.tar.bz2'
                except:
                    return '.bz2'

            # XZ文件头
            if header[:6] == b'\xfd7zXZ\x00':
                # 检查是否是tar.xz
                try:
                    with tarfile.open(file_path, 'r:xz') as tf:
                        return '.tar.xz'
                except:
                    return '.xz'

            return ''
        except Exception:
            return ''

    def delete_service(self, service_name: str, force: bool = False) -> Tuple[bool, str]:
        """删除服务"""
        try:
            # 检查服务是否存在
            service_info = self.db.fetch_one("SELECT id, status FROM services WHERE name = ?", (service_name,))
            if not service_info:
                return False, f"服务 {service_name} 不存在"

            # 检查服务状态
            status_info = self.get_service_status(service_name)
            if status_info['status'] in ['running', 'partially_running'] and not force:
                return False, "请先停止服务再删除"

            # 停止服务
            if status_info['status'] in ['running', 'partially_running']:
                self.stop_service(service_name)
                time.sleep(3)  # 等待停止完成

            # 删除服务目录
            service_path = self.get_service_path(service_name)
            if service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)

            # 删除数据库记录
            self.db.execute_query("DELETE FROM services WHERE name = ?", (service_name,))

            logger.info(f"服务 {service_name} 删除成功")
            return True, "服务删除成功"

        except Exception as e:
            logger.error(f"删除服务失败: {e}")
            return False, f"删除失败: {str(e)}"

    def update_service_status(self, service_name: str, enabled: bool) -> Tuple[bool, str]:
        """更新服务状态（是否启用）"""
        try:
            # 检查服务是否存在
            service_info = self.db.fetch_one("SELECT id FROM services WHERE name = ?", (service_name,))
            if not service_info:
                return False, f"服务 {service_name} 不存在"

            # 更新数据库
            self.db.execute_query(
                "UPDATE services SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                (1 if enabled else 0, service_name)
            )

            return True, f"服务已{'启用' if enabled else '禁用'}"

        except Exception as e:
            logger.error(f"更新服务状态失败: {e}")
            return False, f"更新失败: {str(e)}"

    def get_service_logs(self, service_name: str, tail: int = 100) -> Tuple[bool, str]:
        """获取服务日志"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            project_name = self.get_project_name(service_name)

            # 执行docker-compose logs
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'logs',
                '--tail', str(tail)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=self.get_env_with_docker_host()
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr

        except Exception as e:
            logger.error(f"获取服务日志失败: {e}")
            return False, f"获取失败: {str(e)}"

    def execute_command(self, service_name: str, container_name: str, command: str, user: str = None) -> Tuple[bool, str]:
        """在容器中执行命令"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            project_name = self.get_project_name(service_name)

            # 构建docker-compose exec命令
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'exec'
            ]

            if user:
                cmd.extend(['-u', user])

            cmd.extend([container_name, 'sh', '-c', command])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                env=self.get_env_with_docker_host()
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr

        except subprocess.TimeoutExpired:
            return False, "命令执行超时"
        except Exception as e:
            logger.error(f"执行命令失败: {e}")
            return False, f"执行失败: {str(e)}"

    def resolve_default_container_name(self, service_name: str) -> Optional[str]:
        """解析服务默认容器名（优先Compose服务名）。"""
        try:
            status_info = self.get_service_status(service_name)
            containers = status_info.get('containers') or []
            if not containers:
                return None
            first = containers[0] or {}
            return first.get('Service') or first.get('service') or first.get('Name') or first.get('name')
        except Exception:
            return None

    def start_exec_shell_process(
        self,
        service_name: str,
        container_name: Optional[str] = None,
        shell_cmd: str = '/bin/sh',
        mode: str = 'shell',
        user: Optional[str] = None
    ) -> Tuple[bool, Optional[ExecSession], str]:
        """启动容器交互shell进程（用于WebSocket实时终端）。"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, None, f"服务 {service_name} 不存在"

            resolved_container = (container_name or '').strip() or self.resolve_default_container_name(service_name)
            if not resolved_container:
                return False, None, "无法解析容器名称，请指定container参数"

            project_name = self.get_project_name(service_name)
            terminal_mode = (mode or 'shell').strip().lower()
            detach_sequence = b''

            if terminal_mode == 'attach':
                ps_cmd = [
                    self.docker_compose_bin,
                    '-f', str(compose_file),
                    '-p', project_name,
                    'ps',
                    '-q',
                    resolved_container
                ]
                ps_result = subprocess.run(
                    ps_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=self.get_env_with_docker_host()
                )
                container_id = (ps_result.stdout or '').strip().splitlines()
                if ps_result.returncode != 0 or not container_id:
                    err = (ps_result.stderr or '').strip() or f'无法找到容器: {resolved_container}'
                    return False, None, f'attach失败: {err}'

                # attach 模式退出时必须“脱离”而不是把容器主进程一起带走。
                # 1) --sig-proxy=false: docker attach 客户端退出/收信号时，不向容器转发终止信号
                # 2) --detach-keys=ctrl-p,ctrl-q: WebSocket 关闭时，先发标准脱离序列，再结束 attach 客户端
                cmd = [
                    self.docker_bin,
                    'attach',
                    '--sig-proxy=false',
                    '--detach-keys=ctrl-p,ctrl-q',
                    container_id[0]
                ]
                detach_sequence = b'\x10\x11'
            else:
                requested_shell = (shell_cmd or '').strip() or '/bin/sh'
                # 避免容器不存在 /bin/bash 导致“连上即断开”，对常见 shell 做自动回退。
                if requested_shell in ('/bin/bash', 'bash', '/bin/sh', 'sh'):
                    fallback_script = (
                        'if command -v bash >/dev/null 2>&1; then exec bash; '
                        'elif [ -x /bin/bash ]; then exec /bin/bash; '
                        'elif command -v sh >/dev/null 2>&1; then exec sh; '
                        'else exec /bin/sh; fi'
                    )
                    exec_cmd = ['sh', '-lc', fallback_script]
                else:
                    exec_cmd = ['sh', '-lc', requested_shell]

                base_cmd = [
                    self.docker_compose_bin,
                    '-f', str(compose_file),
                    '-p', project_name,
                    'exec',
                ]
                if user:
                    base_cmd.extend(['-u', user])

                # 终端 shell 需要真正的 TTY 才会有提示符、回显和行编辑能力。
                # 优先通过 `script` 包装 docker compose exec，为浏览器 WS 提供可交互的 PTY。
                script_bin = shutil.which('script')
                if script_bin:
                    interactive_cmd = [*base_cmd, resolved_container, *exec_cmd]
                    cmd = [script_bin, '-qfec', shlex.join(interactive_cmd), '/dev/null']
                else:
                    cmd = [*base_cmd, '-T', resolved_container, *exec_cmd]

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                env=self.get_env_with_docker_host()
            )
            return True, ExecSession(
                process=proc,
                resolved_container=resolved_container,
                mode=terminal_mode,
                detach_sequence=detach_sequence
            ), resolved_container
        except Exception as e:
            logger.error(f"启动容器交互shell失败: {e}")
            return False, None, f"启动交互shell失败: {str(e)}"

    def stop_exec_session(self, session: ExecSession, graceful_timeout: float = 2.0):
        """停止交互终端会话。

        attach 模式优先发送 docker detach 序列，避免把容器主进程一起停掉。
        shell 模式则直接结束子进程。
        """
        try:
            process = session.process if session else None
            if not process or process.poll() is not None:
                return

            if session.mode == 'attach':
                detached = False
                try:
                    if process.stdin and session.detach_sequence:
                        process.stdin.write(session.detach_sequence)
                        process.stdin.flush()
                        detached = True
                except Exception:
                    detached = False

                try:
                    if process.stdin:
                        process.stdin.close()
                except Exception:
                    pass

                if detached:
                    try:
                        process.wait(timeout=graceful_timeout)
                        return
                    except Exception:
                        pass

            process.terminate()
            try:
                process.wait(timeout=graceful_timeout)
            except Exception:
                process.kill()
        except Exception as e:
            logger.warning(f"停止终端会话失败: {e}")

    def restart_all_enabled_services(self):
        """重启所有启用的服务"""
        try:
            services = self.db.fetch_all("SELECT name, status FROM services WHERE enabled = 1")

            for service in services:
                service_name = service['name']
                logger.info(f"检查服务 {service_name} 状态...")

                # 获取当前状态
                status_info = self.get_service_status(service_name)

                if status_info['status'] == 'running':
                    # 检查所有容器是否正常
                    all_healthy = True
                    for container in status_info['containers']:
                        if container.get('State') != 'running' or container.get('Health') == 'unhealthy':
                            all_healthy = False
                            break

                    if all_healthy and status_info['running'] == status_info['total']:
                        logger.info(f"服务 {service_name} 运行正常，跳过重启")
                        continue
                    else:
                        logger.info(f"服务 {service_name} 状态不正常，执行重建")
                        # 先停止再启动
                        self.stop_service(service_name)
                        time.sleep(2)
                        self.start_service(service_name)
                elif status_info['status'] == 'stopped':
                    logger.info(f"服务 {service_name} 已停止，执行启动")
                    self.start_service(service_name)
                else:
                    logger.info(f"服务 {service_name} 状态: {status_info['status']}，执行重启")
                    self.restart_service(service_name)

            logger.info("所有服务检查完成")
        except Exception as e:
            logger.error(f"重启服务失败: {e}")

class StaticFileServer:
    """静态文件服务器"""

    def __init__(self, config: Dict):
        self.config = config
        self.static_dir = Path(config.get('static_dir', './static'))
        self.index_file = config.get('static_index_file', 'index.html')

        # 创建静态文件目录
        self.static_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"静态文件目录: {self.static_dir}")

    def serve_static_file(self, path: str):
        """提供静态文件服务"""
        # 如果路径为空或者是根路径，返回index.html
        if not path or path == '/':
            path = self.index_file

        # 移除开头的斜杠（如果有）
        if path.startswith('/'):
            path = path[1:]

        # 构建完整的文件路径
        file_path = self.static_dir / path

        # 检查文件是否存在
        if file_path.exists() and file_path.is_file():
            # 安全检查：确保文件在静态目录内
            try:
                file_path.relative_to(self.static_dir)
            except ValueError:
                # 试图访问静态目录外的文件
                return jsonify({'error': '禁止访问'}), 403

            # 获取MIME类型
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if not mime_type:
                mime_type = 'application/octet-stream'

            # 检查是否是HTML文件
            if mime_type.startswith('text/html'):
                return send_file(str(file_path), mimetype=mime_type)
            else:
                return send_file(str(file_path), mimetype=mime_type)

        # 如果文件不存在，检查是否是目录，如果是目录则返回目录下的index.html
        elif file_path.exists() and file_path.is_dir():
            index_path = file_path / self.index_file
            if index_path.exists():
                return send_file(str(index_path), mimetype='text/html')

        # 对于单页应用，将所有未找到的路径重定向到index.html
        index_file = self.static_dir / self.index_file
        if index_file.exists():
            # 记录404请求
            logger.debug(f"静态文件未找到: {path}, 重定向到index.html")
            return send_file(str(index_file), mimetype='text/html')

        # 如果连index.html都没有，返回404
        return jsonify({'error': '文件未找到'}), 404

    def get_static_file_info(self, path: str = None) -> Dict:
        """获取静态文件信息"""
        if path:
            file_path = self.static_dir / path
            if file_path.exists():
                return {
                    'exists': True,
                    'path': str(file_path),
                    'is_file': file_path.is_file(),
                    'is_dir': file_path.is_dir(),
                    'size': file_path.stat().st_size if file_path.is_file() else 0,
                    'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                }
            else:
                return {'exists': False, 'path': str(file_path)}
        else:
            # 获取目录信息
            files = []
            total_size = 0

            for item in self.static_dir.rglob('*'):
                if item.is_file():
                    files.append({
                        'name': item.name,
                        'path': str(item.relative_to(self.static_dir)),
                        'size': item.stat().st_size,
                        'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat(),
                        'type': 'file'
                    })
                    total_size += item.stat().st_size
                elif item.is_dir():
                    files.append({
                        'name': item.name,
                        'path': str(item.relative_to(self.static_dir)),
                        'size': 0,
                        'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat(),
                        'type': 'directory'
                    })

            return {
                'static_dir': str(self.static_dir),
                'total_files': len([f for f in files if f['type'] == 'file']),
                'total_dirs': len([f for f in files if f['type'] == 'directory']),
                'total_size': total_size,
                'files': files
            }

class WebServer:
    """WEB服务器"""
    def __init__(self, config_file: str, docker_client=None):
        self.config = ConfigManager.load_config(config_file)
        self.service_manager = ServiceManager(self.config)
        self.system_info_collector = SystemInfoCollector(docker_client)
        self.static_file_server = StaticFileServer(self.config)

        # 设置Flask配置
        app.config['MAX_CONTENT_LENGTH'] = self.config['max_upload_size']
        app.config['SECRET_KEY'] = os.urandom(24)

        # 移除默认的/static前缀，设置静态文件从根目录提供
        app.config['APPLICATION_ROOT'] = '/'

        # 设置静态文件缓存
        app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600  # 1小时缓存

        # 配置静态文件从根目录访问
        self._setup_static_routes()

    def _setup_static_routes(self):
        """设置静态文件路由"""
        # 移除Flask默认的/static前缀
        # 我们将通过自定义路由处理所有静态文件请求
        pass

    def authenticate(self, request):
        """认证检查"""
        token = request.headers.get('X-Auth-Token')
        return token == self.config['token']

    def run(self):
        """运行服务器"""
        # 启动时检查并重启服务
        logger.info("启动时检查服务状态...")
        self.service_manager.restart_all_enabled_services()

        # 启动Flask服务器
        logger.info(f"启动WEB服务器，监听端口 {self.config['port']}")
        try:
            # 创建带有 reuse_port属性的socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config['host'], self.config['port']))
            sock.listen(1)

            # 关闭socket，Flask会自己创建
            sock.close()

            app.run(
                host=self.config['host'],
                port=self.config['port'],
                debug=False,
                threaded=True,
                use_reloader=False
            )
        except Exception as e:
            logger.error(f"WEB服务器启动失败: {e}")
            sys.exit(1)

# ===================== 静态文件服务路由 =====================

@app.route('/', defaults={'path': ''}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def serve_static_files(path):
    """提供静态文件服务（处理所有非API的GET请求）"""
    # 检查是否是API请求
    if request.path.startswith('/api/'):
        # 如果是API请求但未找到对应路由，返回404
        return jsonify({'error': 'API端点未找到'}), 404

    # 检查是否是静态文件管理API
    if request.path.startswith('/api/static/'):
        # 如果是静态文件管理API，返回404（由对应的API路由处理）
        return jsonify({'error': 'API端点未找到'}), 404

    # 提供静态文件
    return static_file_server.serve_static_file(path)

@app.route('/api/static/info', methods=['GET'])
def get_static_file_info():
    """获取静态文件信息"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        path = request.args.get('path')
        info = static_file_server.get_static_file_info(path)

        return jsonify(info)
    except Exception as e:
        logger.error(f"获取静态文件信息失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/static/upload', methods=['POST'])
def upload_static_file():
    """上传静态文件"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到文件'}), 400

        file = request.files['file']
        path = request.form.get('path', '')

        if not file.filename:
            return jsonify({'error': '文件名不能为空'}), 400

        # 构建目标路径
        if path:
            target_dir = static_file_server.static_dir / path
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / file.filename
        else:
            target_path = static_file_server.static_dir / file.filename

        # 保存文件
        file.save(str(target_path))

        logger.info(f"静态文件上传成功: {target_path}")

        return jsonify({
            'message': '文件上传成功',
            'path': str(target_path.relative_to(static_file_server.static_dir)),
            'size': target_path.stat().st_size
        })
    except Exception as e:
        logger.error(f"上传静态文件失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/static/delete', methods=['DELETE'])
def delete_static_file():
    """删除静态文件"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求体必须为JSON'}), 400

        path = data.get('path')
        if not path:
            return jsonify({'error': '文件路径不能为空'}), 400

        # 构建完整路径
        file_path = static_file_server.static_dir / path

        # 检查文件是否存在
        if not file_path.exists():
            return jsonify({'error': '文件不存在'}), 404

        # 检查是否是静态文件目录内的文件
        try:
            file_path.relative_to(static_file_server.static_dir)
        except ValueError:
            return jsonify({'error': '不允许删除静态文件目录外的文件'}), 400

        # 如果是目录，递归删除
        if file_path.is_dir():
            shutil.rmtree(file_path)
            action = '目录删除成功'
        else:
            file_path.unlink()
            action = '文件删除成功'

        logger.info(f"静态文件删除成功: {file_path}")

        return jsonify({
            'message': action,
            'path': path
        })
    except Exception as e:
        logger.error(f"删除静态文件失败: {e}")
        return jsonify({'error': str(e)}), 500

# ===================== 鉴权API =====================

@app.route('/api/auth/validate', methods=['POST'])
def validate_token():
    """验证Token有效性"""
    try:
        # 从请求中获取Token
        auth_token = None

        # 尝试从请求头获取
        auth_token = request.headers.get('X-Auth-Token')

        # 如果请求头中没有，尝试从JSON body获取
        if not auth_token and request.is_json:
            data = request.get_json()
            auth_token = data.get('token')

        # 如果还是没有，尝试从表单数据获取
        if not auth_token:
            auth_token = request.form.get('token')

        # 获取客户端信息
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        request_method = request.method
        request_path = request.path

        # 获取配置中的Token
        config_token = config.get('token', 'default_token_change_me')

        # 验证Token
        token_match = False
        authenticated = False
        message = ""

        if auth_token:
            token_match = (auth_token == config_token)
            if token_match:
                authenticated = True
                message = "Token验证成功"
                logger.info(f"Token验证成功 - 客户端IP: {client_ip}")
            else:
                authenticated = False
                message = "Token验证失败: Token不匹配"
                logger.warning(f"Token验证失败 - 客户端IP: {client_ip}, 提供的Token: {auth_token[:10]}...")
        else:
            authenticated = False
            message = "Token验证失败: 未提供Token"
            logger.warning(f"Token验证失败 - 客户端IP: {client_ip}, 原因: 未提供Token")

        # 创建鉴权结果
        auth_result = AuthResult(
            authenticated=authenticated,
            message=message,
            timestamp=datetime.now().isoformat(),
            token_provided=auth_token or "",
            token_length=len(auth_token) if auth_token else 0,
            token_match=token_match,
            client_ip=client_ip,
            user_agent=user_agent,
            request_method=request_method,
            request_path=request_path
        )

        version_info = _build_agent_version_info()

        # 转换为字典返回
        result_dict = asdict(auth_result)
        result_dict['nacos_agent_version'] = version_info['date']
        result_dict['nacos_agent_version_human'] = version_info['human']
        result_dict['nacos_agent_version_semver'] = version_info['semver']

        # 根据鉴权结果设置HTTP状态码
        status_code = 200 if authenticated else 401

        return jsonify(result_dict), status_code

    except Exception as e:
        logger.error(f"Token验证过程中发生错误: {e}")
        return jsonify({
            'error': '内部服务器错误',
            'details': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/auth/info', methods=['GET'])
def get_auth_info():
    """获取认证信息（无需认证）"""
    try:
        # 获取客户端信息
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        request_method = request.method
        request_path = request.path

        # 检查是否有Token提供
        auth_token = request.headers.get('X-Auth-Token')
        has_token = bool(auth_token)

        # 获取配置中的Token信息（不显示完整Token）
        config_token = config.get('token', 'default_token_change_me')
        token_length = len(config_token)
        token_prefix = config_token[:3] + "..." if len(config_token) > 3 else "***"

        version_info = _build_agent_version_info()
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'client_ip': client_ip,
            'user_agent': user_agent,
            'request_method': request_method,
            'request_path': request_path,
            'has_token_provided': has_token,
            'token_provided_length': len(auth_token) if auth_token else 0,
            'config_token_length': token_length,
            'config_token_prefix': token_prefix,
            'auth_required': True,
            'auth_method': 'X-Auth-Token header or token parameter',
            'nacos_agent_version': version_info['date'],
            'nacos_agent_version_human': version_info['human'],
            'nacos_agent_version_semver': version_info['semver'],
            'message': '此API不需要认证，仅用于获取认证信息'
        })

    except Exception as e:
        logger.error(f"获取认证信息失败: {e}")
        return jsonify({
            'error': '获取认证信息失败',
            'details': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# ===================== 系统信息API =====================

@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    """获取系统基本信息"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        version_info = _build_agent_version_info()
        # 获取系统信息
        system_info = system_info_collector.get_system_info()

        # 将dataclass转换为字典
        def dataclass_to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: dataclass_to_dict(v) for k, v in asdict(obj).items()}
            elif isinstance(obj, list):
                return [dataclass_to_dict(item) for item in obj]
            else:
                return obj

        result = dataclass_to_dict(system_info)
        result['nacos_agent_version'] = version_info['date']
        result['nacos_agent_version_human'] = version_info['human']
        result['nacos_agent_version_semver'] = version_info['semver']

        # 添加格式化信息（便于阅读）
        result['formatted'] = {
            'nacos_agent_version': version_info['date'],
            'nacos_agent_version_human': version_info['human'],
            'nacos_agent_version_semver': version_info['semver'],
            'uptime': format_uptime(result['uptime']),
            'memory': {
                'total': format_bytes(result['memory']['total']),
                'available': format_bytes(result['memory']['available']),
                'used': format_bytes(result['memory']['used']),
                'free': format_bytes(result['memory']['free'])
            },
            'disks': [
                {
                    'device': disk['device'],
                    'mountpoint': disk['mountpoint'],
                    'total': format_bytes(disk['total']),
                    'used': format_bytes(disk['used']),
                    'free': format_bytes(disk['free']),
                    'usage_percent': f"{disk['usage_percent']:.1f}%"
                }
                for disk in result['disks']
            ],
            'docker': {
                'images_size': format_bytes(result['docker']['images_size']),
                'containers': f"{result['docker']['containers_running']}/{result['docker']['containers_total']} 运行中"
            }
        }

        return jsonify(result)
    except Exception as e:
        logger.error(f"获取系统信息失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/metrics', methods=['GET'])
def get_system_metrics():
    """获取系统性能指标（轻量版）"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        # 使用缓存或快速获取基本信息
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # 获取Docker容器状态
        docker_containers = []
        if docker_client:
            try:
                containers = docker_client.containers.list(all=True)
                for container in containers[:10]:  # 限制返回数量
                    docker_containers.append({
                        'id': container.short_id,
                        'name': container.name,
                        'status': container.status,
                        'image': container.attrs['Config']['Image'],
                        'created': container.attrs['Created']
                    })
            except Exception as e:
                logger.warning(f"获取Docker容器信息失败: {e}")

        # 获取磁盘使用情况
        disk_usage = []
        partitions = psutil.disk_partitions(all=False)
        for partition in partitions[:5]:  # 限制返回数量
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage.append({
                    'mountpoint': partition.mountpoint,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                })
            except:
                continue

        # 获取网络IO
        net_io = psutil.net_io_counters()

        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu': {
                'percent': cpu_percent,
                'cores': psutil.cpu_count(logical=True),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else []
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_percent': swap.percent
            },
            'disk': disk_usage,
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'docker': {
                'containers_total': len(docker_containers) if docker_client else 0,
                'containers': docker_containers
            }
        }

        # 添加格式化信息
        metrics['formatted'] = {
            'cpu_percent': f"{cpu_percent:.1f}%",
            'memory_percent': f"{memory.percent:.1f}%",
            'memory_used': format_bytes(memory.used),
            'memory_total': format_bytes(memory.total),
            'network_sent': format_bytes(net_io.bytes_sent),
            'network_recv': format_bytes(net_io.bytes_recv)
        }

        return jsonify(metrics)
    except Exception as e:
        logger.error(f"获取系统指标失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/processes', methods=['GET'])
def get_system_processes():
    """获取系统进程信息"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        processes = []

        # 获取所有进程
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status',
                                         'cpu_percent', 'memory_percent',
                                         'memory_info', 'create_time', 'cmdline']):
            try:
                pinfo = proc.info

                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'username': pinfo.get('username', ''),
                    'status': pinfo['status'],
                    'cpu_percent': pinfo.get('cpu_percent', 0),
                    'memory_percent': pinfo.get('memory_percent', 0),
                    'memory_rss': pinfo['memory_info'].rss if pinfo.get('memory_info') else 0,
                    'create_time': pinfo['create_time'],
                    'cmdline': ' '.join(pinfo['cmdline']) if pinfo.get('cmdline') else ''
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # 排序和分页
        sort_by = request.args.get('sort', 'cpu_percent')
        order = request.args.get('order', 'desc')
        limit = int(request.args.get('limit', 50))

        reverse = (order == 'desc')

        if sort_by in ['cpu_percent', 'memory_percent', 'memory_rss']:
            processes.sort(key=lambda x: x[sort_by], reverse=reverse)

        # 分页
        page = int(request.args.get('page', 1))
        per_page = min(limit, 100)  # 限制每页最大100条

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

        paginated_processes = processes[start_idx:end_idx]

        return jsonify({
            'total': len(processes),
            'page': page,
            'per_page': per_page,
            'processes': paginated_processes
        })
    except Exception as e:
        logger.error(f"获取进程信息失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/docker/stats', methods=['GET'])
def get_docker_stats():
    """获取Docker容器统计信息"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if not docker_client:
            return jsonify({'error': 'Docker客户端不可用'}), 503

        containers = docker_client.containers.list(all=True)
        container_stats = []

        for container in containers:
            try:
                # 获取容器统计信息
                stats = container.stats(stream=False)

                # 计算CPU使用率
                cpu_stats = stats.get('cpu_stats', {})
                precpu_stats = stats.get('precpu_stats', {})

                cpu_delta = cpu_stats.get('cpu_usage', {}).get('total_usage', 0) - \
                            precpu_stats.get('cpu_usage', {}).get('total_usage', 0)
                system_delta = cpu_stats.get('system_cpu_usage', 0) - \
                               precpu_stats.get('system_cpu_usage', 0)

                cpu_percent = 0.0
                if system_delta > 0 and cpu_delta > 0:
                    cpu_percent = (cpu_delta / system_delta) * cpu_stats.get('online_cpus', 1) * 100

                # 获取内存使用
                memory_stats = stats.get('memory_stats', {})
                memory_usage = memory_stats.get('usage', 0)
                memory_limit = memory_stats.get('limit', 0)

                # 获取网络统计
                networks = stats.get('networks', {})
                network_rx = sum(net.get('rx_bytes', 0) for net in networks.values())
                network_tx = sum(net.get('tx_bytes', 0) for net in networks.values())

                container_stats.append({
                    'id': container.short_id,
                    'name': container.name,
                    'status': container.status,
                    'image': container.attrs['Config']['Image'],
                    'cpu_percent': round(cpu_percent, 2),
                    'memory_usage': memory_usage,
                    'memory_limit': memory_limit,
                    'memory_percent': round((memory_usage / memory_limit * 100) if memory_limit > 0 else 0, 2),
                    'network_rx': network_rx,
                    'network_tx': network_tx,
                    'pids': stats.get('pids_stats', {}).get('current', 0)
                })
            except Exception as e:
                logger.warning(f"获取容器 {container.name} 统计信息失败: {e}")
                continue

        # 按CPU使用率排序
        container_stats.sort(key=lambda x: x['cpu_percent'], reverse=True)

        # 添加格式化信息
        for stat in container_stats:
            stat['formatted'] = {
                'memory_usage': format_bytes(stat['memory_usage']),
                'memory_limit': format_bytes(stat['memory_limit']),
                'network_rx': format_bytes(stat['network_rx']),
                'network_tx': format_bytes(stat['network_tx'])
            }

        return jsonify(container_stats)
    except Exception as e:
        logger.error(f"获取Docker统计信息失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/docker/images', methods=['GET'])
def get_docker_images():
    """获取Docker镜像信息"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if not docker_client:
            return jsonify({'error': 'Docker客户端不可用'}), 503

        images = docker_client.images.list()
        image_list = []

        for image in images:
            tags = image.tags
            if not tags:
                continue

            image_list.append({
                'id': image.short_id,
                'tags': tags,
                'created': image.attrs['Created'],
                'size': image.attrs['Size'],
                'virtual_size': image.attrs.get('VirtualSize', 0),
                'labels': image.attrs.get('Labels', {})
            })

        # 按大小排序
        image_list.sort(key=lambda x: x['size'], reverse=True)

        # 添加格式化信息
        for img in image_list:
            img['formatted'] = {
                'size': format_bytes(img['size']),
                'virtual_size': format_bytes(img['virtual_size'])
            }

        return jsonify(image_list)
    except Exception as e:
        logger.error(f"获取Docker镜像信息失败: {e}")
        return jsonify({'error': str(e)}), 500

# ===================== 原有的API路由 =====================

def _services_cache_ttl_sec() -> int:
    try:
        return max(1, int(config.get('services_cache_ttl_sec', 5)))
    except Exception:
        return 5


def _build_services_snapshot() -> List[Dict[str, Any]]:
    services = db_conn.execute(
        "SELECT id, name, path, project_name, template_id, template_name, tags_json, enabled, status, created_at, updated_at "
        "FROM services ORDER BY name"
    ).fetchall()

    result: List[Dict[str, Any]] = []
    for service in services:
        service_dict = dict(service)
        service_dict['tags'] = service_manager.normalize_tags(service_dict.get('tags_json'))
        service_dict['real_status'] = service_manager.get_service_status(service['name'])
        result.append(service_dict)
    return result


def _get_services_snapshot(force_refresh: bool = False) -> List[Dict[str, Any]]:
    ttl = _services_cache_ttl_sec()
    is_refresh_owner = False

    for _ in range(6):
        now = time.time()
        with _services_cache_lock:
            cached_payload = _services_cache.get('payload')
            cached_ts = float(_services_cache.get('ts') or 0.0)
            cache_fresh = bool(cached_payload is not None and (now - cached_ts) < ttl)

            if not force_refresh and cache_fresh:
                return cached_payload

            if _services_cache.get('refreshing'):
                if cached_payload is not None and not force_refresh:
                    return cached_payload
            else:
                _services_cache['refreshing'] = True
                is_refresh_owner = True
                break
        time.sleep(0.05)

    with _services_cache_lock:
        if not is_refresh_owner:
            cached_payload = _services_cache.get('payload')
            if cached_payload is not None and not force_refresh:
                return cached_payload

    try:
        payload = _build_services_snapshot()
    except Exception as exc:
        with _services_cache_lock:
            fallback = _services_cache.get('payload')
            _services_cache['last_error'] = str(exc)
            _services_cache['refreshing'] = False
        if fallback is not None:
            logger.warning(f"/api/services 刷新失败，回退缓存: {exc}")
            return fallback
        raise

    with _services_cache_lock:
        _services_cache['payload'] = payload
        _services_cache['ts'] = time.time()
        _services_cache['last_error'] = ''
        _services_cache['refreshing'] = False
    return payload

# 健康检查
@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    version_info = _build_agent_version_info()
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': version_info['semver'],
        'nacos_agent_version': version_info['date'],
        'nacos_agent_version_human': version_info['human']
    })

@app.route('/api/services', methods=['GET'])
def list_services():
    """列出所有服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        force_refresh = request.args.get('refresh') == '1'
        return jsonify(_get_services_snapshot(force_refresh=force_refresh))
    except Exception as e:
        logger.error(f"列出服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>', methods=['GET'])
def get_service(service_name):
    """获取服务详情"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        service = db_conn.execute(
            "SELECT id, name, path, project_name, template_id, template_name, tags_json, enabled, status, created_at, updated_at "
            "FROM services WHERE name = ?",
            (service_name,)
        ).fetchone()

        if not service:
            return jsonify({'error': '服务不存在'}), 404

        service_dict = dict(service)
        service_dict['tags'] = service_manager.normalize_tags(service_dict.get('tags_json'))
        # 获取实时状态
        status_info = service_manager.get_service_status(service_name)
        service_dict['real_status'] = status_info

        # 读取YAML文件内容
        compose_file = service_manager.get_compose_file(service_name)
        if compose_file.exists():
            with open(compose_file, 'r', encoding='utf-8') as f:
                service_dict['yaml_content'] = f.read()

        return jsonify(service_dict)
    except Exception as e:
        logger.error(f"获取服务详情失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/operation-status', methods=['GET'])
def get_service_operation_status(service_name):
    """获取服务操作中间状态与进度"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        service = db_conn.execute(
            "SELECT id, name FROM services WHERE name = ?",
            (service_name,)
        ).fetchone()

        if not service:
            return jsonify({'error': '服务不存在'}), 404

        op = service_manager.get_service_operation_status(service_name)
        return jsonify({
            'service_name': service_name,
            'operation': op
        })
    except Exception as e:
        logger.error(f"获取服务操作状态失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/yaml', methods=['POST'])
def create_service_from_yaml():
    """从YAML创建服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求体必须为JSON'}), 400

        service_name = data.get('name')
        yaml_content = data.get('yaml')
        files = data.get('files') if isinstance(data.get('files'), list) else []
        template_name = str(data.get('template_name') or '').strip()
        tags = service_manager.normalize_tags(data.get('tags'))
        template_id = data.get('template_id')
        try:
            template_id = int(template_id) if template_id not in (None, '', []) else None
        except (TypeError, ValueError):
            template_id = None

        if not service_name or not yaml_content:
            return jsonify({'error': '服务名称和YAML内容不能为空'}), 400

        success, message = service_manager.create_service_from_yaml(
            service_name,
            yaml_content,
            template_name=template_name,
            template_id=template_id,
            tags=tags,
            files=files,
        )

        if success:
            return jsonify({'message': message}), 201
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"创建服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/zip', methods=['POST'])
def create_service_from_zip():
    """从压缩包创建服务（支持多种格式）"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到文件'}), 400

        file = request.files['file']
        service_name = request.form.get('name')
        template_name = str(request.form.get('template_name') or '').strip()
        tags = service_manager.normalize_tags(request.form.get('tags'))
        template_id = request.form.get('template_id')
        try:
            template_id = int(template_id) if template_id not in (None, '', []) else None
        except (TypeError, ValueError):
            template_id = None

        if not service_name:
            return jsonify({'error': '服务名称不能为空'}), 400

        if not file.filename:
            return jsonify({'error': '文件名不能为空'}), 400

        # 保存临时文件
        temp_dir = tempfile.mkdtemp()

        # 生成唯一的文件名
        file_ext = Path(file.filename).suffix
        temp_file_name = f"{service_name}_{uuid.uuid4().hex[:8]}{file_ext}"
        archive_path = Path(temp_dir) / temp_file_name

        file.save(str(archive_path))

        # 调用方法来处理压缩包（支持多种格式）
        success, message = service_manager.create_service_from_zip(
            service_name,
            str(archive_path),
            template_name=template_name,
            template_id=template_id,
            tags=tags
        )

        # 清理临时文件
        shutil.rmtree(temp_dir, ignore_errors=True)

        if success:
            return jsonify({
                'message': message,
                'service': service_name,
                'file_type': file_ext
            }), 201
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"从压缩包创建服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/start', methods=['POST'])
def start_service(service_name):
    """启动服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.start_service(service_name)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"启动服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/stop', methods=['POST'])
def stop_service(service_name):
    """停止服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.stop_service(service_name)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"停止服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/restart', methods=['POST'])
def restart_service(service_name):
    """重启服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.restart_service(service_name)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"重启服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/update', methods=['POST'])
def update_service(service_name):
    """更新服务镜像并重启"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.update_service(service_name)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"更新服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>', methods=['DELETE'])
def delete_service(service_name):
    """删除服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        force = request.args.get('force', 'false').lower() == 'true'
        success, message = service_manager.delete_service(service_name, force)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"删除服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/enable', methods=['PUT'])
def enable_service(service_name):
    """启用服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.update_service_status(service_name, True)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"启用服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/disable', methods=['PUT'])
def disable_service(service_name):
    """禁用服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        success, message = service_manager.update_service_status(service_name, False)

        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"禁用服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/logs', methods=['GET'])
def get_service_logs(service_name):
    """获取服务日志"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        tail = int(request.args.get('tail', 100))
        success, message = service_manager.get_service_logs(service_name, tail)

        if success:
            return jsonify({'logs': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"获取服务日志失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/exec', methods=['POST'])
def execute_service_command(service_name):
    """在服务容器中执行命令"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求体必须为JSON'}), 400

        container_name = data.get('container')
        command = data.get('command')
        user = data.get('user')

        if not container_name or not command:
            return jsonify({'error': '容器名称和命令不能为空'}), 400

        success, message = service_manager.execute_command(service_name, container_name, command, user)

        if success:
            return jsonify({'output': message}), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"执行命令失败: {e}")
        return jsonify({'error': str(e)}), 500


@sock.route('/api/services/<service_name>/exec/ws')
def execute_service_command_ws(ws, service_name):
    """在服务容器内执行交互式命令（WebSocket实时终端）。"""
    try:
        if not authenticate_ws_request(ws):
            ws.send("\r\n[AUTH] 认证失败，连接关闭。\r\n")
            ws.close()
            return

        env = ws.environ or {}
        params = {}
        raw_qs = env.get('QUERY_STRING') or ''
        for pair in raw_qs.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = unquote(v)

        container_name = (params.get('container') or '').strip() or None
        shell_cmd = (params.get('shell') or '/bin/sh').strip() or '/bin/sh'
        mode = (params.get('mode') or 'shell').strip().lower() or 'shell'
        user = (params.get('user') or '').strip() or None

        ok, session, resolved = service_manager.start_exec_shell_process(
            service_name=service_name,
            container_name=container_name,
            shell_cmd=shell_cmd,
            mode=mode,
            user=user
        )
        if not ok or not session:
            ws.send(f"\r\n[ERROR] {resolved}\r\n")
            ws.close()
            return

        ws.send(f"\r\n[OK] 已连接服务 {service_name} 容器 {resolved}，mode={mode}，shell={shell_cmd}\r\n\r\n")

        stop_event = threading.Event()
        send_lock = threading.Lock()
        process = session.process

        def _pump_stream(stream_obj, prefix: str = ''):
            try:
                while not stop_event.is_set():
                    chunk = stream_obj.read(1024)
                    if not chunk:
                        break
                    text = chunk.decode('utf-8', errors='replace')
                    with send_lock:
                        ws.send(prefix + text if prefix else text)
            except Exception:
                pass

        stdout_thread = threading.Thread(target=_pump_stream, args=(process.stdout, ''), daemon=True)
        stderr_thread = threading.Thread(target=_pump_stream, args=(process.stderr, ''), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        try:
            while not stop_event.is_set():
                msg = ws.receive()
                if msg is None:
                    break

                try:
                    parsed = json.loads(msg)
                    if isinstance(parsed, dict):
                        msg_type = parsed.get('type')
                        if msg_type == 'ping':
                            # 浏览器/Ingress 空闲保活，不写入终端，仅回一个空帧保活双向链路
                            try:
                                ws.send('')
                            except Exception:
                                pass
                            continue
                        if msg_type == 'resize':
                            # 当前后端使用非TTY(-T)模式，先忽略resize请求，避免协议报错
                            continue
                        # 兼容前端历史格式: {"resize":{"rows":..,"cols":..}}
                        if 'resize' in parsed:
                            continue
                        if msg_type == 'input':
                            msg = parsed.get('data', '')
                except Exception:
                    pass

                if isinstance(msg, str) and process.stdin:
                    process.stdin.write(msg.encode('utf-8', errors='replace'))
                    process.stdin.flush()
        finally:
            stop_event.set()
            try:
                if session:
                    service_manager.stop_exec_session(session)
            except Exception:
                pass
            try:
                ws.close()
            except Exception:
                pass

    except Exception as e:
        # 客户端主动关闭(1000/1005等)属于常见行为，不应作为高优先级错误刷屏。
        msg = str(e)
        if 'Connection closed' in msg:
            logger.info(f"WebSocket会话结束: {msg}")
        else:
            logger.error(f"WebSocket执行命令失败: {e}", exc_info=True)
        try:
            ws.send(f"\r\n[ERROR] {str(e)}\r\n")
            ws.close()
        except Exception:
            pass


# 在现有代码的基础上，添加以下内容：

@app.route('/api/validate/data', methods=['GET'])
def validate_data_consistency():
    """校验服务的文件状态与数据库记录是否一致"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        # 获取数据库中的所有服务
        db_services = db_conn.execute(
            "SELECT name, path FROM services"
        ).fetchall()

        validation_results = {
            'total': len(db_services),
            'consistent': [],
            'inconsistent': [],
            'orphaned_folders': []
        }

        # 检查数据库中的每个服务
        for service in db_services:
            service_name = service['name']
            db_path = service['path']

            # 检查服务文件夹是否存在
            service_path = Path(db_path)
            if not service_path.exists():
                validation_results['inconsistent'].append({
                    'service': service_name,
                    'issue': '文件夹不存在',
                    'db_path': db_path,
                    'actual_path': '不存在'
                })
                continue

            # 检查docker-compose.yaml文件是否存在
            compose_file = service_path / 'docker-compose.yaml'
            if not compose_file.exists():
                validation_results['inconsistent'].append({
                    'service': service_name,
                    'issue': 'docker-compose.yaml文件不存在',
                    'db_path': db_path,
                    'actual_path': str(compose_file)
                })
                continue

            # 检查YAML文件是否可以解析
            try:
                with open(compose_file, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    parsed = yaml.safe_load(yaml_content)

                    if not parsed or 'services' not in parsed:
                        validation_results['inconsistent'].append({
                            'service': service_name,
                            'issue': 'docker-compose.yaml格式错误',
                            'db_path': db_path,
                            'actual_path': str(compose_file)
                        })
                        continue
            except Exception as e:
                validation_results['inconsistent'].append({
                    'service': service_name,
                    'issue': f'YAML解析失败: {str(e)}',
                    'db_path': db_path,
                    'actual_path': str(compose_file)
                })
                continue

            # 如果所有检查都通过，标记为一致
            validation_results['consistent'].append({
                'service': service_name,
                'path': db_path,
                'status': 'ok'
            })

        # 检查孤儿文件夹（存在文件夹但在数据库中没有记录）
        compose_root = Path(service_manager.config['compose_root'])
        if compose_root.exists():
            for item in compose_root.iterdir():
                if item.is_dir():
                    # 检查是否是docker-compose服务目录
                    docker_compose_yaml = item / 'docker-compose.yaml'
                    docker_compose_yml = item / 'docker-compose.yml'

                    if docker_compose_yaml.exists() or docker_compose_yml.exists():
                        # 检查数据库中是否有记录
                        db_record = db_conn.execute(
                            "SELECT name FROM services WHERE name = ? OR path = ?",
                            (item.name, str(item))
                        ).fetchone()

                        if not db_record:
                            validation_results['orphaned_folders'].append({
                                'folder': item.name,
                                'path': str(item),
                                'issue': '存在服务文件夹但数据库中没有记录'
                            })

        validation_results['summary'] = {
            'consistent_count': len(validation_results['consistent']),
            'inconsistent_count': len(validation_results['inconsistent']),
            'orphaned_count': len(validation_results['orphaned_folders']),
            'consistency_percentage': round(len(validation_results['consistent']) / max(validation_results['total'], 1) * 100, 2)
        }

        return jsonify(validation_results)

    except Exception as e:
        logger.error(f"数据一致性校验失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate/services', methods=['GET'])
def validate_services_state():
    """校验服务状态是否符合配置（使能/非使能）"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        # 获取所有服务
        services = db_conn.execute(
            "SELECT id, name, enabled, status FROM services"
        ).fetchall()

        validation_results = {
            'total': len(services),
            'valid': [],
            'invalid': [],
            'health_checks': {
                'enabled_healthy': [],
                'enabled_unhealthy': [],
                'disabled_running': [],
                'disabled_stopped': []
            }
        }

        for service in services:
            service_name = service['name']
            enabled = service['enabled'] == 1
            db_status = service['status']

            # 获取实时服务状态
            real_status_info = service_manager.get_service_status(service_name)
            real_status = real_status_info.get('status', 'unknown')
            containers = real_status_info.get('containers', [])

            service_validation = {
                'service': service_name,
                'enabled': enabled,
                'db_status': db_status,
                'real_status': real_status,
                'containers_count': len(containers),
                'containers': []
            }

            # 检查每个容器的健康状态
            healthy_containers = 0
            unhealthy_containers = 0

            for container in containers:
                container_name = container.get('Service', 'unknown')
                container_state = container.get('State', 'unknown')
                container_health = container.get('Health', 'unknown')

                # 判断容器是否健康
                is_healthy = False
                if container_state == 'running':
                    if container_health in ['healthy', 'starting',  None] or len(container_health) == 0:
                        # 如果没有健康检查配置，running状态就认为是健康的
                        # 如果有健康检查，必须是healthy状态
                        if container_health == 'healthy' or container_health is None or len(container_health) == 0:
                            is_healthy = True
                            healthy_containers += 1
                        else:
                            unhealthy_containers += 1
                    elif container_health == 'unhealthy':
                        unhealthy_containers += 1
                    else:
                        # 其他健康状态
                        unhealthy_containers += 1
                else:
                    unhealthy_containers += 1

                service_validation['containers'].append({
                    'name': container_name,
                    'state': container_state,
                    'health': container_health,
                    'healthy': is_healthy
                })

            service_validation['healthy_containers'] = healthy_containers
            service_validation['unhealthy_containers'] = unhealthy_containers
            service_validation['all_healthy'] = (healthy_containers > 0 and unhealthy_containers == 0)

            # 验证服务状态是否符合配置
            is_valid = True
            validation_errors = []

            if enabled:
                # 启用的服务应该运行
                if real_status not in ['running', 'partially_running']:
                    is_valid = False
                    validation_errors.append(f"服务已启用但状态为{real_status}")

                # 检查容器健康状态
                if unhealthy_containers > 0:
                    is_valid = False
                    validation_errors.append(f"有{unhealthy_containers}个容器不健康")

                # 记录到健康检查分类
                if is_valid and healthy_containers > 0:
                    validation_results['health_checks']['enabled_healthy'].append(service_name)
                else:
                    validation_results['health_checks']['enabled_unhealthy'].append({
                        'service': service_name,
                        'issues': validation_errors
                    })
            else:
                # 禁用的服务应该停止
                if real_status != 'stopped' and real_status != 'not_found':
                    is_valid = False
                    validation_errors.append(f"服务已禁用但状态为{real_status}")

                # 记录到健康检查分类
                if real_status == 'stopped':
                    validation_results['health_checks']['disabled_stopped'].append(service_name)
                else:
                    validation_results['health_checks']['disabled_running'].append({
                        'service': service_name,
                        'issues': validation_errors
                    })

            service_validation['valid'] = is_valid
            service_validation['validation_errors'] = validation_errors

            if is_valid:
                validation_results['valid'].append(service_validation)
            else:
                validation_results['invalid'].append(service_validation)

        # 生成校验摘要
        validation_results['summary'] = {
            'valid_count': len(validation_results['valid']),
            'invalid_count': len(validation_results['invalid']),
            'enabled_healthy_count': len(validation_results['health_checks']['enabled_healthy']),
            'enabled_unhealthy_count': len(validation_results['health_checks']['enabled_unhealthy']),
            'disabled_stopped_count': len(validation_results['health_checks']['disabled_stopped']),
            'disabled_running_count': len(validation_results['health_checks']['disabled_running']),
            'validation_percentage': round(len(validation_results['valid']) / max(validation_results['total'], 1) * 100, 2)
        }

        # 添加建议的修复操作
        validation_results['suggested_fixes'] = []

        # 对于禁用的但仍在运行的服务，建议停止
        for invalid_service in validation_results['invalid']:
            if not invalid_service['enabled'] and invalid_service['real_status'] != 'stopped':
                validation_results['suggested_fixes'].append({
                    'service': invalid_service['service'],
                    'action': 'stop',
                    'reason': '服务已禁用但仍在运行',
                    'command': f'POST /api/services/{invalid_service["service"]}/stop'
                })

        # 对于启用的但不健康的服务，建议重建
        for invalid_service in validation_results['invalid']:
            if invalid_service['enabled'] and not invalid_service['all_healthy']:
                validation_results['suggested_fixes'].append({
                    'service': invalid_service['service'],
                    'action': 'restart',
                    'reason': f'服务已启用但{invalid_service["unhealthy_containers"]}个容器不健康',
                    'command': f'POST /api/services/{invalid_service["service"]}/restart'
                })

        return jsonify(validation_results)

    except Exception as e:
        logger.error(f"服务状态校验失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate/fix', methods=['POST'])
def fix_validation_issues():
    """修复校验发现的问题"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '请求体必须为JSON'}), 400

        fix_type = data.get('type', 'all')  # 'all', 'orphaned', 'inconsistent', 'state'
        auto_execute = data.get('auto_execute', False)

        fix_results = {
            'total_fixes': 0,
            'executed_fixes': 0,
            'failed_fixes': [],
            'fix_operations': []
        }

        # 1. 先执行数据一致性校验
        if fix_type in ['all', 'orphaned', 'inconsistent']:
            # 检查孤儿文件夹
            compose_root = Path(service_manager.config['compose_root'])
            if compose_root.exists():
                for item in compose_root.iterdir():
                    if item.is_dir():
                        docker_compose_yaml = item / 'docker-compose.yaml'
                        docker_compose_yml = item / 'docker-compose.yml'

                        if docker_compose_yaml.exists() or docker_compose_yml.exists():
                            # 检查数据库中是否有记录
                            db_record = db_conn.execute(
                                "SELECT name FROM services WHERE name = ? OR path = ?",
                                (item.name, str(item))
                            ).fetchone()

                            if not db_record:
                                fix_results['total_fixes'] += 1

                                if auto_execute:
                                    try:
                                        # 尝试从YAML文件解析服务名
                                        service_name = None
                                        project_name = None
                                        yaml_file = None

                                        if docker_compose_yaml.exists():
                                            yaml_file = docker_compose_yaml
                                        elif docker_compose_yml.exists():
                                            yaml_file = docker_compose_yml

                                        if yaml_file:
                                            with open(yaml_file, 'r', encoding='utf-8') as f:
                                                parsed = yaml.safe_load(f)
                                                # 尝试从YAML中获取服务名
                                                if parsed and 'name' in parsed:
                                                    project_name = parsed['name']
                                                elif parsed and 'services' in parsed:
                                                    # 使用第一个服务名
                                                    first_service = next(iter(parsed['services'].keys()))
                                                    service_name = f"{item.name}_{first_service}"

                                        service_name = service_name or item.name
                                        project_name = str(project_name or service_name)

                                        # 插入数据库记录
                                        db_conn.execute(
                                            "INSERT INTO services (name, path, project_name, status, enabled) VALUES (?, ?, ?, 'stopped', 0)",
                                            (service_name, str(item), project_name)
                                        )
                                        db_conn.commit()

                                        fix_results['executed_fixes'] += 1
                                        fix_results['fix_operations'].append({
                                            'type': 'orphaned_folder',
                                            'folder': item.name,
                                            'action': 'added_to_database',
                                            'service_name': service_name,
                                            'status': 'success'
                                        })
                                    except Exception as e:
                                        fix_results['failed_fixes'].append({
                                            'folder': item.name,
                                            'error': str(e),
                                            'status': 'failed'
                                        })
                                else:
                                    fix_results['fix_operations'].append({
                                        'type': 'orphaned_folder',
                                        'folder': item.name,
                                        'action': 'needs_manual_fix',
                                        'suggestion': '添加到数据库或删除文件夹'
                                    })

        # 2. 修复服务状态不一致
        if fix_type in ['all', 'state']:
            # 获取所有服务
            services = db_conn.execute(
                "SELECT name, enabled FROM services"
            ).fetchall()

            for service in services:
                service_name = service['name']
                enabled = service['enabled'] == 1

                # 获取实时状态
                real_status_info = service_manager.get_service_status(service_name)
                real_status = real_status_info.get('status', 'unknown')

                needs_fix = False
                action = None

                if enabled and real_status not in ['running', 'partially_running']:
                    needs_fix = True
                    action = 'start'
                elif not enabled and real_status != 'stopped':
                    needs_fix = True
                    action = 'stop'

                if needs_fix:
                    fix_results['total_fixes'] += 1

                    if auto_execute:
                        try:
                            if action == 'start':
                                success, message = service_manager.start_service(service_name)
                            else:
                                success, message = service_manager.stop_service(service_name)

                            if success:
                                fix_results['executed_fixes'] += 1
                                fix_results['fix_operations'].append({
                                    'type': 'state_mismatch',
                                    'service': service_name,
                                    'action': action,
                                    'status': 'success',
                                    'message': message
                                })
                            else:
                                fix_results['failed_fixes'].append({
                                    'service': service_name,
                                    'action': action,
                                    'error': message,
                                    'status': 'failed'
                                })
                        except Exception as e:
                            fix_results['failed_fixes'].append({
                                'service': service_name,
                                'error': str(e),
                                'status': 'failed'
                            })
                    else:
                        fix_results['fix_operations'].append({
                            'type': 'state_mismatch',
                            'service': service_name,
                            'action': action,
                            'suggestion': f'执行{action}操作'
                        })

        fix_results['summary'] = {
            'fix_success_rate': round(fix_results['executed_fixes'] / max(fix_results['total_fixes'], 1) * 100, 2)
        }

        return jsonify(fix_results)

    except Exception as e:
        logger.error(f"修复校验问题失败: {e}")
        return jsonify({'error': str(e)}), 500

# 在ServiceManager类中添加一个新的方法，用于修复特定服务
def fix_service_state(self, service_name: str, target_state: str) -> Tuple[bool, str]:
    """修复服务状态到目标状态"""
    try:
        # 获取当前状态
        current_status_info = self.get_service_status(service_name)
        current_status = current_status_info.get('status', 'unknown')

        if target_state == 'running':
            if current_status in ['running', 'partially_running']:
                return True, "服务已经在运行"
            else:
                return self.start_service(service_name)
        elif target_state == 'stopped':
            if current_status == 'stopped':
                return True, "服务已经停止"
            else:
                return self.stop_service(service_name)
        else:
            return False, f"未知的目标状态: {target_state}"

    except Exception as e:
        logger.error(f"修复服务状态失败: {e}")
        return False, f"修复失败: {str(e)}"


@app.route('/api/upgrade', methods=['POST'])
def upgrade_server():
    """升级服务器"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到文件'}), 400

        file = request.files['file']

        # 检查文件类型
        if not file.filename.endswith('.py'):
            return jsonify({'error': '只能上传Python文件'}), 400

        # 计算文件哈希
        file_content = file.read()
        file_hash = hashlib.md5(file_content).hexdigest()

        # 备份当前文件
        current_file = Path(__file__).resolve()
        backup_file = current_file.parent / f"{current_file.stem}.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}.py"

        with open(current_file, 'rb') as f:
            current_content = f.read()

        with open(backup_file, 'wb') as f:
            f.write(current_content)

        # 写入新文件
        with open(current_file, 'wb') as f:
            f.write(file_content)

        logger.info(f"服务器升级成功，备份文件: {backup_file}")

        # 计划重启
        threading.Timer(2, restart_server).start()

        return jsonify({
            'message': '升级成功，服务器将在2秒后重启',
            'backup_file': str(backup_file),
            'file_hash': file_hash
        }), 200
    except Exception as e:
        logger.error(f"升级服务器失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/files', methods=['GET'])
def get_service_directory_structure(service_name):
    """获取服务文件夹结构"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        result = service_manager.get_service_directory_structure(service_name)

        if 'error' in result:
            return jsonify(result), 404 if '不存在' in result['error'] else 500

        return jsonify(result), 200
    except Exception as e:
        logger.error(f"获取服务文件夹结构失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/files/download', methods=['GET'])
def download_service_file(service_name):
    """下载服务文件"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({'error': '文件路径不能为空'}), 400

        success, message, content = service_manager.get_service_file(service_name, file_path)

        if not success:
            return jsonify({'error': message}), 404

        # 创建临时文件用于下载
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=Path(file_path).suffix)
        temp_file.write(content)
        temp_file.close()

        # 获取文件名
        filename = Path(file_path).name

        logger.info(f"下载服务文件: {service_name}/{file_path}")

        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"下载服务文件失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_name>/files/update', methods=['PUT'])
def update_service_file(service_name):
    """更新服务文件（在线编辑）"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        # 获取文件路径和内容
        file_path = request.form.get('path')
        file_content = request.files.get('file')

        if not file_path:
            return jsonify({'error': '文件路径不能为空'}), 400

        if not file_content:
            return jsonify({'error': '文件内容不能为空'}), 400

        # 读取文件内容
        content = file_content.read()

        # 如果是文本文件，也支持直接传文本内容
        text_content = request.form.get('content')
        if not content and text_content:
            content = text_content.encode('utf-8')

        if not content:
            return jsonify({'error': '文件内容不能为空'}), 400

        # 更新文件
        success, message = service_manager.update_service_file(service_name, file_path, content)

        if success:
            # 如果是docker-compose文件，重新加载服务配置
            if Path(file_path).name in ['docker-compose.yaml', 'docker-compose.yml', 'compose.yaml', 'compose.yml']:
                logger.info(f"检测到docker-compose文件更新，重新加载服务配置: {service_name}")
                # 可以在这里添加服务重启逻辑（如果需要）
                # 例如：自动重启服务
                # service_manager.restart_service(service_name)

            return jsonify({
                'message': message,
                'service': service_name,
                'file': file_path,
                'size': len(content)
            }), 200
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"更新服务文件失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/services/now', methods=['POST'])
def report_services_now():
    """手动触发一次服务上报"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if not service_reporter:
            return jsonify({'error': 'service reporter not initialized'}), 500
        service_reporter._report_full()
        return jsonify({'message': 'service report triggered'}), 200
    except Exception as e:
        logger.error(f"手动触发服务上报失败: {e}")
        return jsonify({'error': str(e)}), 500

class AgentServiceReporter:
    """Agent服务状态上报器（周期全量上报）"""

    def __init__(self, config: Dict, service_manager: ServiceManager, logger_obj):
        self.config = config
        self.service_manager = service_manager
        self.logger = logger_obj
        self.enabled = bool(config.get('agent_service_report_enabled', False))
        self.platform_agent_url = (config.get('platform_agent_url') or '').rstrip('/')
        self.interval_sec = max(int(config.get('agent_service_report_interval_sec', 30)), 10)
        self.timeout_sec = max(int(config.get('platform_agent_report_timeout_sec', 15)), 5)
        self.agent_key = (config.get('agent_key') or '').strip()
        self._stop_event = threading.Event()
        self._thread = None

    def set_agent_key(self, agent_key: str):
        if agent_key and not self.agent_key:
            self.agent_key = agent_key.strip()

    @staticmethod
    def normalize_tags(tags: Any) -> List[str]:
        """Normalize tags for service reporting with stable dedup behavior."""
        return ServiceManager.normalize_tags(tags)

    @staticmethod
    def _normalize_tags_safe(tags: Any) -> List[str]:
        """
        Backward-compatible tag normalizer for reporter.
        防御旧版本/热更新不一致导致 normalize_tags 缺失或异常时，避免中断周期上报线程。
        """
        try:
            normalize = getattr(ServiceManager, 'normalize_tags', None)
            if callable(normalize):
                return normalize(tags)
        except Exception:
            pass

        # Fallback parser: keep behavior close to ServiceManager.normalize_tags
        if isinstance(tags, str):
            try:
                parsed = json.loads(tags)
                if isinstance(parsed, list):
                    tags = parsed
                else:
                    tags = [item.strip() for item in tags.split(',')]
            except Exception:
                tags = [item.strip() for item in tags.split(',')]
        elif not isinstance(tags, (list, tuple, set)):
            tags = []

        seen = set()
        normalized: List[str] = []
        for item in tags:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    def _extract_ports_from_compose(self, compose_data: Dict) -> Dict[str, str]:
        ports: Dict[str, str] = {}
        try:
            services = compose_data.get('services') or {}
            for _, svc in services.items():
                svc_ports = svc.get('ports') or []
                for idx, item in enumerate(svc_ports):
                    if isinstance(item, str):
                        ports[f'port_{idx}'] = item
                    elif isinstance(item, dict):
                        key = str(item.get('protocol') or item.get('name') or f'port_{idx}')
                        val = str(item.get('published') or item.get('target') or item.get('port') or '')
                        ports[key] = val
                    else:
                        ports[f'port_{idx}'] = str(item)
            return ports
        except Exception:
            return {}

    def _collect_services_snapshot(self) -> List[Dict[str, Any]]:
        services = db_conn.execute(
            "SELECT name, status, project_name, template_id, template_name, tags_json FROM services ORDER BY name"
        ).fetchall()

        snapshot: List[Dict[str, Any]] = []
        for row in services:
            service_name = row['name']
            service_status = row['status']
            image = ''
            images: List[str] = []
            ports: Dict[str, str] = {}
            status_info: Dict[str, Any] = {}

            try:
                status_payload = self.service_manager.get_service_status(service_name)
                if isinstance(status_payload, dict):
                    status_info = status_payload
                if isinstance(status_info, dict):
                    service_status = status_info.get('status') or service_status
                    containers = status_info.get('containers') or []
                    if isinstance(containers, list):
                        seen_images = set()
                        for container in containers:
                            if not isinstance(container, dict):
                                continue
                            container_image = str(container.get('Image') or container.get('image') or '').strip()
                            if not container_image or container_image in seen_images:
                                continue
                            seen_images.add(container_image)
                            images.append(container_image)
            except Exception:
                pass

            try:
                compose_file = self.service_manager.get_compose_file(service_name)
                if compose_file.exists():
                    compose_data = self.service_manager.parse_compose_file(compose_file)
                    if isinstance(compose_data, dict):
                        svc_map = compose_data.get('services') or {}
                        if svc_map:
                            if not images:
                                for service_def in svc_map.values():
                                    if not isinstance(service_def, dict):
                                        continue
                                    fallback_image = str(service_def.get('image') or '').strip()
                                    if not fallback_image or fallback_image in images:
                                        continue
                                    images.append(fallback_image)
                        ports = self._extract_ports_from_compose(compose_data)
            except Exception:
                pass

            if images:
                image = images[0]

            snapshot.append({
                'name': service_name,
                'status': str(service_status or 'unknown'),
                'image': image,
                'images': images,
                'ports': ports,
                'real_status': status_info,
                'project_name': str(row['project_name'] or '').strip(),
                'template_id': row['template_id'],
                'template_name': str(row['template_name'] or '').strip(),
                'tags': self._normalize_tags_safe(row['tags_json']),
            })

        return snapshot

    def _resolve_report_ip(self) -> str:
        try:
            ip = get_sothoth_ip_address()
            if ip:
                return str(ip)
        except Exception:
            pass
        try:
            return str(socket.gethostbyname(socket.gethostname()))
        except Exception:
            return ''

    def _report_full(self):
        if not self.enabled:
            return
        if not self.platform_agent_url:
            return
        if not self.agent_key:
            self.logger.warning("服务上报跳过：agent_key 为空")
            return

        report_ip = self._resolve_report_ip()
        workspace_id = str(self.config.get('workspace_id') or '').strip()
        hostname = socket.gethostname()
        payload = {
            'agent_key': self.agent_key,
            'project_id': workspace_id,
            'hostname': hostname,
            'ip_address': report_ip,
            'full_name': (
                f"{workspace_id}-{self.agent_key}-{hostname}-{report_ip}"
                if workspace_id and self.agent_key and report_ip else ''
            ),
            'services': self._collect_services_snapshot()
        }

        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.config.get('token', '')
        }
        url = f"{self.platform_agent_url}/api/agent/report/services/full"
        resp = requests.post(url, headers=headers, json=payload, timeout=(5, self.timeout_sec))
        if resp.status_code >= 300:
            self.logger.warning(f"服务上报失败: status={resp.status_code}, body={resp.text[:200]}")
        else:
            self.logger.info(f"服务上报成功: agent={self.agent_key}, count={len(payload['services'])}")

    def _loop(self):
        # 启动后立即全量上报一次
        try:
            self._report_full()
        except Exception as e:
            self.logger.warning(f"首次服务上报失败: {e}")

        while not self._stop_event.wait(self.interval_sec):
            try:
                self._report_full()
            except Exception as e:
                self.logger.warning(f"周期服务上报失败: {e}")

    def start(self):
        if not self.enabled:
            self.logger.info("服务上报功能未启用")
            return
        if not self.platform_agent_url:
            self.logger.info("服务上报功能已启用，但 platform_agent_url 未配置，跳过启动")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="agent-service-reporter")
        self._thread.start()
        self.logger.info(
            f"服务上报线程已启动: url={self.platform_agent_url}, interval={self.interval_sec}s, agent_key={self.agent_key or 'N/A'}"
        )

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

# ===================== 辅助函数 =====================

def authenticate_request():
    """认证请求"""
    token = request.headers.get('X-Auth-Token')
    return token == config.get('token')

def authenticate_ws_request(ws) -> bool:
    """认证WebSocket请求（支持query token与header）。"""
    try:
        expected = config.get('token')
        env = ws.environ or {}
        query = env.get('QUERY_STRING') or ''

        token_from_query = None
        for pair in query.split('&'):
            if '=' not in pair:
                continue
            k, v = pair.split('=', 1)
            if k in ('token', 'auth_token'):
                token_from_query = unquote(v)
                break

        token_from_header = env.get('HTTP_X_AUTH_TOKEN')
        token = token_from_query or token_from_header
        return bool(token) and token == expected
    except Exception:
        return False

def format_bytes(bytes_value: int) -> str:
    """格式化字节数为人类可读格式"""
    if bytes_value == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_index = 0

    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024
        unit_index += 1

    return f"{bytes_value:.2f} {units[unit_index]}"

def format_uptime(seconds: int) -> str:
    """格式化运行时间"""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}天")
    if hours > 0:
        parts.append(f"{hours}小时")
    if minutes > 0:
        parts.append(f"{minutes}分钟")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}秒")

    return ' '.join(parts)


def _build_agent_version_info() -> Dict[str, str]:
    """
    统一构建版本信息：
    - date: 机器可解析版本（日期构建号）
    - human: 人类可读版本
    - semver: 近似语义化版本（便于排序/展示）
    """
    # 优先读取构建产物中的版本文件（由build.sh动态生成）
    if VERSION_FILE.exists():
        try:
            with open(VERSION_FILE, 'r', encoding='utf-8') as f:
                payload = json.load(f) or {}
            date_value = str(payload.get('date') or '').strip()
            human_value = str(payload.get('human') or '').strip()
            semver_value = str(payload.get('semver') or '').strip()
            if date_value and human_value and semver_value:
                return {
                    'date': date_value,
                    'human': human_value,
                    'semver': semver_value
                }
        except Exception:
            pass

    # 兜底：开发环境无version.json时，使用当前时间构造
    raw_date = datetime.now().strftime('%Y%m%d.%H%M%S')
    custom_human = ''

    # 支持: YYYYMMDD.XXXX / YYYYMMDD-XXXX / YYYYMMDDXXXX
    cleaned = raw_date.replace('-', '.')
    m = re.match(r'^(\d{4})(\d{2})(\d{2})(?:\.?(\d{2,8}))?$', cleaned)
    if m:
        y, mo, d, build = m.group(1), m.group(2), m.group(3), (m.group(4) or '')
        auto_human = f"v{y}.{mo}.{d}" + (f" (build {build})" if build else '')
        semver = f"{int(y)}.{int(mo)}.{int(d)}" + (f"+{build}" if build else '')
        return {
            'date': raw_date,
            'human': custom_human or auto_human,
            'semver': semver
        }

    # 无法解析时回退：仍保证有可读输出
    fallback_human = custom_human or f"build-{raw_date}"
    return {
        'date': raw_date,
        'human': fallback_human,
        'semver': raw_date
    }

def restart_server():
    """重启服务器"""
    logger.info("重启服务器...")
    os.execv(sys.executable, [sys.executable] + sys.argv)

def extract_uuid_from_config(file_path):
    """
    从配置文件中提取UUID值
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 使用正则表达式匹配uuid行
        pattern = r'uuid\s*=\s*([a-fA-F0-9-]+)'
        match = re.search(pattern, content)

        if match:
            return match.group(1)
        else:
            print("未找到UUID值")
            return None

    except FileNotFoundError:
        print(f"文件未找到: {file_path}")
        return None
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return None

# ===================== 全局实例 =====================
service_manager = None
system_info_collector = None
static_file_server = None
service_reporter = None

def main():
    """主函数"""
    global logger, config, service_manager, system_info_collector, docker_client, static_file_server, service_reporter

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    setup_grace_exit(graceful_exit)
    parser = argparse.ArgumentParser(description='Docker Compose服务管理WEB服务器')
    parser.add_argument('-c', '--config', required=True, help='配置文件路径')

    args = parser.parse_args()
    config = ConfigManager.load_config(args.config)
    logger = setup_logger(os.path.join(config['log_dir'],"nacos_client.log"))

    # 初始化Docker客户端，带重试逻辑
    max_retries = 10
    retry_interval = 10  # 秒

    for retry_count in range(max_retries):
        try:
            logger.info(f"尝试初始化Docker客户端 (第 {retry_count + 1} 次)...")
            docker_client = docker.DockerClient(base_url=config['docker_socket'])
            docker_client.ping()
            logger.info("Docker客户端初始化成功")
            break
        except Exception as e:
            logger.error(f"Docker客户端初始化失败: {e}")

            if retry_count < max_retries - 1:
                logger.info(f"等待 {retry_interval} 秒后重试...")
                time.sleep(retry_interval)
            else:
                logger.error(f"Docker客户端初始化失败超过 {max_retries} 次，进程退出")
                sys.exit(255)

    # 读取 sothothv2_agent.ini 配置文件获取 UUID
    uuid_value = None
    try:
        ini_file_path = Path(config['root_dir']) / "config" / "sothothv2_agent.ini"
        logger.info(f"尝试读取配置文件: {ini_file_path}")

        if ini_file_path.exists():
            uuid_value = extract_uuid_from_config(str(ini_file_path))
        else:
            logger.warning(f"配置文件不存在: {ini_file_path}")
    except Exception as e:
        logger.error(f"读取sothothv2_agent.ini配置文件失败: {e}")

    if not config.get('agent_key') and uuid_value:
        config['agent_key'] = uuid_value

    # 启动服务器
    server = WebServer(args.config, docker_client)
    service_manager = server.service_manager
    system_info_collector = SystemInfoCollector(docker_client)
    static_file_server = server.static_file_server
    service_reporter = AgentServiceReporter(config, service_manager, logger)
    if uuid_value:
        service_reporter.set_agent_key(uuid_value)
    service_reporter.start()

    # 创建示例静态文件（如果目录为空）
    static_dir = Path(config.get('static_dir', './static'))
    index_file = static_dir / config.get('static_index_file', 'index.html')

    # 启动服务器
    get_sothoth_ip_address()

    # 启动Nacos监控线程，传入UUID
    nacos_server_url = config.get('nacos_server_url')
    workspace_id = config.get('workspace_id')

    if uuid_value:
        logger.info(f"启动Nacos监控线程，参数: nacos_server_url={nacos_server_url}, workspace_id={workspace_id}, uuid={uuid_value}")
        nacos_thread = threading.Thread(target=start_nacos, args=[nacos_server_url, workspace_id, uuid_value])
    else:
        logger.info(f"启动Nacos监控线程，参数: nacos_server_url={nacos_server_url}, workspace_id={workspace_id}")
        nacos_thread = threading.Thread(target=start_nacos, args=[nacos_server_url, workspace_id, 'unknown_id'])

    nacos_thread.start()

    server.run()
