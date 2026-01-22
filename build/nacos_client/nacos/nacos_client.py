import dns.resolver
import socket

g_nacos_server_ip = None
g_nacos_server_port = None
g_nacos_heartbeat_time = None
g_workspace_id = None
g_node_uuid = None

def set_process_dns(nameservers):
    """
    设置当前进程使用的DNS解析器
    nameservers: DNS服务器列表，如 ['8.8.8.8', '8.8.4.4']
    """
    # 创建自定义解析器
    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameservers

    # 覆盖默认的socket.getaddrinfo
    original_getaddrinfo = socket.getaddrinfo

    def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        try:
            # 尝试使用自定义DNS解析
            answers = resolver.resolve(host, 'A')
            addresses = [str(rdata) for rdata in answers]

            # 转换为getaddrinfo格式
            results = []
            for addr in addresses:
                # 根据family参数过滤地址类型
                if family == socket.AF_INET or family == 0:
                    if '.' in addr:  # IPv4
                        results.append((socket.AF_INET, type, proto, '', (addr, port)))
                if family == socket.AF_INET6 or family == 0:
                    if ':' in addr:  # IPv6
                        results.append((socket.AF_INET6, type, proto, '', (addr, port, 0, 0)))

            if results:
                return results
        except Exception:
            pass

        # 如果自定义解析失败，回退到系统默认
        print(f"failed do custom getaddrinfo, try original: {host}")
        return original_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = custom_getaddrinfo
    return resolver


if __name__ == '__main__':
    resolver = set_process_dns(['10.96.0.10'])
    from nacos_client_main import main
    main()