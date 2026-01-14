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
import shutil
import time
import uuid
import hashlib
import signal
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import docker
from docker.errors import DockerException, APIError
from common_utils import setup_logger,setup_grace_exit,get_sothoth_ip_address
from nacos_client_monitor import start_nacos,graceful_exit
from urllib.parse import urlparse

# 全局变量
app = Flask(__name__)
CORS(app)
config = {}
db_conn = None
docker_client = None
server_should_stop = False
logger = None

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
                'database_file': './docker_manager.db'
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
                                                               enabled INTEGER DEFAULT 1,
                                                               status TEXT DEFAULT 'stopped',
                                                               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                       ''')

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
        self.db = DatabaseManager(config['database_file'])

        # 创建服务目录
        self.compose_root.mkdir(parents=True, exist_ok=True)

        # 初始化Docker客户端
        self.init_docker_client()

    def init_docker_client(self):
        """初始化Docker客户端"""
        global docker_client
        try:
            docker_client = docker.DockerClient(base_url=self.config['docker_socket'])
            docker_client.ping()
            logger.info("Docker客户端初始化成功")
        except Exception as e:
            logger.error(f"Docker客户端初始化失败: {e}")
            docker_client = None

    def get_service_path(self, service_name: str) -> Path:
        """获取服务路径"""
        return self.compose_root / service_name

    def get_compose_file(self, service_name: str) -> Path:
        """获取compose文件路径"""
        return self.get_service_path(service_name) / 'service.yaml'

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
            if not compose_file.exists():
                return {'status': 'not_found', 'containers': []}

            # 获取项目名称（使用文件夹名）
            project_name = service_name

            # 使用docker-compose ps命令获取容器状态
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
                cwd=self.get_service_path(service_name)
            )

            if result.returncode == 0:
                containers = json.loads(result.stdout)
                running_count = sum(1 for c in containers if c.get('State') == 'running')
                total_count = len(containers)

                status = 'running' if running_count == total_count > 0 else 'partially_running'
                if total_count == 0:
                    status = 'stopped'

                return {
                    'status': status,
                    'containers': containers,
                    'running': running_count,
                    'total': total_count
                }
            else:
                return {'status': 'unknown', 'containers': []}

        except Exception as e:
            logger.error(f"获取服务状态失败: {e}")
            return {'status': 'error', 'error': str(e)}

    def start_service(self, service_name: str) -> Tuple[bool, str]:
        """启动服务"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            # 检查服务状态
            status_info = self.get_service_status(service_name)
            if status_info['status'] == 'running':
                return True, "服务已在运行"

            # 获取项目名称
            project_name = service_name

            # 执行docker-compose up -d
            cmd = [
                self.docker_compose_bin,
                '-f', str(compose_file),
                '-p', project_name,
                'up',
                '-d'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.get_service_path(service_name)
            )

            if result.returncode == 0:
                # 更新数据库状态
                self.db.execute_query(
                    "UPDATE services SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                return True, "服务启动成功"
            else:
                return False, f"启动失败: {result.stderr}"

        except Exception as e:
            logger.error(f"启动服务失败: {e}")
            return False, f"启动失败: {str(e)}"

    def stop_service(self, service_name: str) -> Tuple[bool, str]:
        """停止服务"""
        try:
            compose_file = self.get_compose_file(service_name)
            if not compose_file.exists():
                return False, f"服务 {service_name} 不存在"

            # 获取项目名称
            project_name = service_name

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
                cwd=self.get_service_path(service_name)
            )

            if result.returncode == 0:
                # 更新数据库状态
                self.db.execute_query(
                    "UPDATE services SET status = 'stopped', updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (service_name,)
                )
                return True, "服务停止成功"
            else:
                return False, f"停止失败: {result.stderr}"

        except Exception as e:
            logger.error(f"停止服务失败: {e}")
            return False, f"停止失败: {str(e)}"

    def restart_service(self, service_name: str) -> Tuple[bool, str]:
        """重启服务"""
        success, message = self.stop_service(service_name)
        if success:
            time.sleep(2)  # 等待2秒
            return self.start_service(service_name)
        return False, message

    def create_service_from_yaml(self, service_name: str, yaml_content: str) -> Tuple[bool, str]:
        """从YAML创建服务"""
        try:
            # 验证服务名称
            if not service_name or not service_name.isalnum():
                return False, "服务名称只能包含字母和数字"

            # 检查服务是否已存在
            existing = self.db.fetch_one("SELECT id FROM services WHERE name = ?", (service_name,))
            if existing:
                return False, f"服务 {service_name} 已存在"

            # 创建服务目录
            service_path = self.get_service_path(service_name)
            service_path.mkdir(parents=True, exist_ok=False)

            # 保存YAML文件
            compose_file = service_path / 'service.yaml'
            with open(compose_file, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            # 验证YAML格式
            try:
                parsed = yaml.safe_load(yaml_content)
                if not parsed or 'services' not in parsed:
                    shutil.rmtree(service_path)
                    return False, "YAML文件必须包含services部分"
            except yaml.YAMLError as e:
                shutil.rmtree(service_path)
                return False, f"YAML格式错误: {e}"

            # 插入数据库记录
            self.db.execute_query(
                "INSERT INTO services (name, path, status) VALUES (?, ?, 'stopped')",
                (service_name, str(service_path))
            )

            logger.info(f"服务 {service_name} 创建成功")
            return True, "服务创建成功"

        except Exception as e:
            logger.error(f"创建服务失败: {e}")
            # 清理已创建的目录
            service_path = self.get_service_path(service_name)
            if service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"创建失败: {str(e)}"

    def create_service_from_zip(self, service_name: str, zip_file_path: str) -> Tuple[bool, str]:
        """从ZIP文件创建服务"""
        temp_dir = None
        try:
            # 验证服务名称
            if not service_name or not service_name.isalnum():
                return False, "服务名称只能包含字母和数字"

            # 检查服务是否已存在
            existing = self.db.fetch_one("SELECT id FROM services WHERE name = ?", (service_name,))
            if existing:
                return False, f"服务 {service_name} 已存在"

            # 创建临时目录解压文件
            temp_dir = tempfile.mkdtemp()

            # 解压ZIP文件
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # 查找service.yaml文件
            yaml_files = list(Path(temp_dir).rglob('service.yaml'))
            yaml_files.extend(list(Path(temp_dir).rglob('docker-compose.yaml')))
            yaml_files.extend(list(Path(temp_dir).rglob('docker-compose.yml')))

            if not yaml_files:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, "未找到service.yaml或docker-compose.yaml文件"

            # 使用第一个找到的YAML文件
            source_yaml = yaml_files[0]

            # 读取并验证YAML
            with open(source_yaml, 'r', encoding='utf-8') as f:
                yaml_content = f.read()

            parsed = yaml.safe_load(yaml_content)
            if not parsed or 'services' not in parsed:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return False, "YAML文件必须包含services部分"

            # 创建服务目录
            service_path = self.get_service_path(service_name)
            service_path.mkdir(parents=True, exist_ok=False)

            # 复制所有文件到服务目录
            for item in Path(temp_dir).iterdir():
                dest = service_path / item.name
                if item.is_dir():
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

            # 确保service.yaml文件存在
            target_yaml = service_path / 'service.yaml'
            if not target_yaml.exists():
                shutil.copy2(source_yaml, target_yaml)

            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
            temp_dir = None

            # 插入数据库记录
            self.db.execute_query(
                "INSERT INTO services (name, path, status) VALUES (?, ?, 'stopped')",
                (service_name, str(service_path))
            )

            logger.info(f"服务 {service_name} 从ZIP创建成功")
            return True, "服务创建成功"

        except zipfile.BadZipFile:
            return False, "无效的ZIP文件"
        except Exception as e:
            logger.error(f"从ZIP创建服务失败: {e}")
            # 清理
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            service_path = self.get_service_path(service_name)
            if service_path.exists():
                shutil.rmtree(service_path, ignore_errors=True)
            return False, f"创建失败: {str(e)}"

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

            # 获取项目名称
            project_name = service_name

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
                cwd=self.get_service_path(service_name)
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

            # 获取项目名称
            project_name = service_name

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
                timeout=30
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

class WebServer:
    """WEB服务器"""

    def __init__(self, config_file: str):
        self.config = ConfigManager.load_config(config_file)
        self.service_manager = ServiceManager(self.config)

        # 设置Flask配置
        app.config['MAX_CONTENT_LENGTH'] = self.config['max_upload_size']
        app.config['SECRET_KEY'] = os.urandom(24)

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
        app.run(
            host=self.config['host'],
            port=self.config['port'],
            debug=False
        )

# API路由
@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/services', methods=['GET'])
def list_services():
    """列出所有服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        services = db_conn.execute(
            "SELECT id, name, path, enabled, status, created_at, updated_at FROM services ORDER BY name"
        ).fetchall()

        result = []
        for service in services:
            service_dict = dict(service)
            # 获取实时状态
            status_info = service_manager.get_service_status(service['name'])
            service_dict['real_status'] = status_info
            result.append(service_dict)

        return jsonify(result)
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
            "SELECT id, name, path, enabled, status, created_at, updated_at FROM services WHERE name = ?",
            (service_name,)
        ).fetchone()

        if not service:
            return jsonify({'error': '服务不存在'}), 404

        service_dict = dict(service)
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

        if not service_name or not yaml_content:
            return jsonify({'error': '服务名称和YAML内容不能为空'}), 400

        success, message = service_manager.create_service_from_yaml(service_name, yaml_content)

        if success:
            return jsonify({'message': message}), 201
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"创建服务失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/zip', methods=['POST'])
def create_service_from_zip():
    """从ZIP文件创建服务"""
    if not authenticate_request():
        return jsonify({'error': '认证失败'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到文件'}), 400

        file = request.files['file']
        service_name = request.form.get('name')

        if not service_name:
            return jsonify({'error': '服务名称不能为空'}), 400

        # 保存临时文件
        temp_dir = tempfile.mkdtemp()
        zip_path = Path(temp_dir) / f'{service_name}.zip'
        file.save(zip_path)

        success, message = service_manager.create_service_from_zip(service_name, str(zip_path))

        # 清理临时文件
        shutil.rmtree(temp_dir, ignore_errors=True)

        if success:
            return jsonify({'message': message}), 201
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        logger.error(f"从ZIP创建服务失败: {e}")
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

            # 检查service.yaml文件是否存在
            compose_file = service_path / 'service.yaml'
            if not compose_file.exists():
                validation_results['inconsistent'].append({
                    'service': service_name,
                    'issue': 'service.yaml文件不存在',
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
                            'issue': 'service.yaml格式错误',
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
                    service_yaml = item / 'service.yaml'
                    docker_compose_yaml = item / 'docker-compose.yaml'
                    docker_compose_yml = item / 'docker-compose.yml'

                    if service_yaml.exists() or docker_compose_yaml.exists() or docker_compose_yml.exists():
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
                    if container_health in ['healthy', 'starting', None]:
                        # 如果没有健康检查配置，running状态就认为是健康的
                        # 如果有健康检查，必须是healthy状态
                        if container_health == 'healthy' or container_health is None:
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
                        service_yaml = item / 'service.yaml'
                        docker_compose_yaml = item / 'docker-compose.yaml'
                        docker_compose_yml = item / 'docker-compose.yml'

                        if service_yaml.exists() or docker_compose_yaml.exists() or docker_compose_yml.exists():
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
                                        yaml_file = None

                                        if service_yaml.exists():
                                            yaml_file = service_yaml
                                        elif docker_compose_yaml.exists():
                                            yaml_file = docker_compose_yaml
                                        elif docker_compose_yml.exists():
                                            yaml_file = docker_compose_yml

                                        if yaml_file:
                                            with open(yaml_file, 'r', encoding='utf-8') as f:
                                                parsed = yaml.safe_load(f)
                                                # 尝试从YAML中获取服务名
                                                if parsed and 'name' in parsed:
                                                    service_name = parsed['name']
                                                elif parsed and 'services' in parsed:
                                                    # 使用第一个服务名
                                                    first_service = next(iter(parsed['services'].keys()))
                                                    service_name = f"{item.name}_{first_service}"

                                        service_name = service_name or item.name

                                        # 插入数据库记录
                                        db_conn.execute(
                                            "INSERT INTO services (name, path, status, enabled) VALUES (?, ?, 'stopped', 0)",
                                            (service_name, str(item))
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

def authenticate_request():
    """认证请求"""
    token = request.headers.get('X-Auth-Token')
    return token == config.get('token')

def restart_server():
    """重启服务器"""
    logger.info("重启服务器...")
    os.execv(sys.executable, [sys.executable] + sys.argv)

# 全局实例
service_manager = None

def main():
    """主函数"""
    global logger

    setup_grace_exit(graceful_exit)
    parser = argparse.ArgumentParser(description='Docker Compose服务管理WEB服务器')
    parser.add_argument('-c', '--config', required=True, help='配置文件路径')

    args = parser.parse_args()
    config = ConfigManager.load_config(args.config)
    logger = setup_logger(os.path.join(config['root_dir'],"var/log/nacos_client.log"))
    get_sothoth_ip_address()
    # 启动服务器
    server = WebServer(args.config)
    global service_manager
    service_manager = server.service_manager
    nacos_thread = threading.Thread(target=start_nacos,args=[config['nacos_server_url']])
    nacos_thread.start()
    server.run()

if __name__ == '__main__':
    main()