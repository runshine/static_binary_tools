package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "time"
    "strings"
    "sync"
    "sort"
    "encoding/json"
    "github.com/google/uuid"
    "gopkg.in/ini.v1"
    "github.com/robfig/cron/v3"
)

// Monitor配置结构体
type MonitorConfig struct {
    Workspace    string `ini:"workspace"`
    ProjectID    string `ini:"project_id"`
    ServerAddr   string `ini:"server_addr"`
    ServerPort   string `ini:"server_port"`
    UUID         string `ini:"uuid"`
    LogLevel     string `ini:"log_level"`
    LogPath      string `ini:"log_path"`
    Foreground   bool   `ini:"foreground"`
}

// 服务配置结构体
type ServiceConfig struct {
    Name         string `json:"name"`
    StartCmd     string `json:"start_cmd"`     // 必选
    StopCmd      string `json:"stop_cmd"`      // 可选
    RestartCmd   string `json:"restart_cmd"`   // 可选
    PIDFile      string `json:"pid_file"`      // 必选
    StdoutLog    string `json:"stdout_log"`    // 可选
    StderrLog    string `json:"stderr_log"`    // 可选
    WorkDir      string `json:"work_dir"`      // 可选
    MonitorMode  string `json:"monitor_mode"`  // "self" 或 "monitor"
    CheckInterval int   `json:"check_interval"` // 检查间隔，默认10秒
    MaxFailures  int    `json:"max_failures"`   // 最大失败次数，默认6次
}

// 服务运行状态
type ServiceStatus struct {
    Service     *ServiceConfig
    Process     *os.Process
    PID         int
    StartTime   time.Time
    FailCount   int
    IsRunning   bool
    LastCheck   time.Time
    mutex       sync.RWMutex
}

// 全局变量
var (
    configFile  = flag.String("config", "monitor.ini", "配置文件路径")
    workspace   = flag.String("workspace", "", "工作空间目录")
    projectID   = flag.String("project-id", "", "项目ID")
    serverAddr  = flag.String("server-addr", "", "服务器地址")
    serverPort  = flag.String("server-port", "", "服务器端口")
    uuidFlag    = flag.String("uuid", "", "Agent UUID")
    logLevel    = flag.String("log-level", "info", "日志级别")
    logPath     = flag.String("log-path", "", "日志目录")
    foreground  = flag.Bool("foreground", false, "在前台运行")
    versionFlag = flag.Bool("version", false, "显示版本信息")

    monitorConfig MonitorConfig
    services      map[string]*ServiceStatus
    serviceMutex  sync.RWMutex
    logger        *log.Logger
    cronScheduler *cron.Cron
)

const (
    Version = "1.0.0"
    DefaultCheckInterval = 10 // 默认检查间隔10秒
    DefaultMaxFailures = 6    // 默认最大失败次数
)

func init() {
    // 初始化日志
    logger = log.New(os.Stdout, "[Monitor] ", log.LstdFlags|log.Lshortfile)
}

func main() {
    // 解析命令行参数
    flag.Parse()

    if *versionFlag {
        fmt.Printf("Monitor Agent Version: %s\n", Version)
        return
    }

    // 检查配置文件是否存在
    if _, err := os.Stat(*configFile); err == nil {
        // 配置文件存在，从配置文件读取
        loadConfigFromFile(*configFile)
    } else {
        // 配置文件不存在，从命令行参数读取并写入配置文件
        loadConfigFromFlags()
        saveConfigToFile(*configFile)
    }

    // 设置日志级别和路径
    setupLogger()

    // 检查必要参数
    if monitorConfig.Workspace == "" || monitorConfig.ProjectID == "" ||
       monitorConfig.ServerAddr == "" || monitorConfig.ServerPort == "" {
        logger.Fatal("workspace, project-id, server-addr, server-port are required")
    }

    // 如果没有UUID，生成一个
    if monitorConfig.UUID == "" {
        monitorConfig.UUID = uuid.New().String()
        saveConfigToFile(*configFile)
    }

    // 如果不是前台运行，则作为守护进程运行
    if !monitorConfig.Foreground && os.Getppid() != 1 {
        daemonize()
        return
    }

    logger.Printf("Monitor Agent started. UUID: %s", monitorConfig.UUID)
    logger.Printf("Workspace: %s", monitorConfig.Workspace)
    logger.Printf("Project ID: %s", monitorConfig.ProjectID)
    logger.Printf("Server: %s:%s", monitorConfig.ServerAddr, monitorConfig.ServerPort)

    // 初始化服务
    services = make(map[string]*ServiceStatus)

    // 创建service_config目录
    serviceConfigDir := filepath.Join(monitorConfig.Workspace, "service_config")
    if err := os.MkdirAll(serviceConfigDir, 0755); err != nil {
        logger.Printf("Failed to create service config directory: %v", err)
    }

    // 加载服务配置
    loadServiceConfigs(serviceConfigDir)

    // 启动cron定时任务
    startMonitorCron()

    // 启动所有服务
    startAllServices()

    // 保持主进程运行
    keepAlive()
}

func loadConfigFromFile(filename string) {
    cfg, err := ini.Load(filename)
    if err != nil {
        logger.Fatalf("Failed to load config file: %v", err)
    }

    err = cfg.MapTo(&monitorConfig)
    if err != nil {
        logger.Fatalf("Failed to map config: %v", err)
    }
}

func loadConfigFromFlags() {
    monitorConfig.Workspace = *workspace
    monitorConfig.ProjectID = *projectID
    monitorConfig.ServerAddr = *serverAddr
    monitorConfig.ServerPort = *serverPort
    monitorConfig.UUID = *uuidFlag
    monitorConfig.LogLevel = *logLevel
    monitorConfig.LogPath = *logPath
    monitorConfig.Foreground = *foreground
}

func saveConfigToFile(filename string) {
    cfg := ini.Empty()
    err := ini.ReflectFrom(cfg, &monitorConfig)
    if err != nil {
        logger.Fatalf("Failed to reflect config: %v", err)
    }

    err = cfg.SaveTo(filename)
    if err != nil {
        logger.Fatalf("Failed to save config file: %v", err)
    }

    logger.Printf("Config saved to %s", filename)
}

func setupLogger() {
    // 设置日志级别
//     level := strings.ToLower(monitorConfig.LogLevel)
    // 这里可以实现日志级别过滤，简化起见直接输出所有级别

    // 设置日志输出路径
    if monitorConfig.LogPath != "" {
        logFile := filepath.Join(monitorConfig.LogPath, "monitor.log")
        file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
        if err == nil {
            logger.SetOutput(file)
        } else {
            logger.Printf("Failed to open log file: %v", err)
        }
    }
}

func daemonize() {
    // 创建守护进程
    cmd := exec.Command(os.Args[0], os.Args[1:]...)
    cmd.Env = os.Environ()

    // 启动子进程
    if err := cmd.Start(); err != nil {
        logger.Fatalf("Failed to start daemon: %v", err)
    }

    fmt.Printf("Daemon started with PID: %d\n", cmd.Process.Pid)
    os.Exit(0)
}

func loadServiceConfigs(configDir string) {
    // 查找所有_service.json文件
    pattern := filepath.Join(configDir, "*_service.json")
    files, err := filepath.Glob(pattern)
    if err != nil {
        logger.Printf("Failed to find service config files: %v", err)
        return
    }

    // 按文件名排序
    sort.Strings(files)

    for _, file := range files {
        loadServiceConfig(file)
    }
}

func loadServiceConfig(filename string) {
    data, err := os.ReadFile(filename)
    if err != nil {
        logger.Printf("Failed to read service config %s: %v", filename, err)
        return
    }

    var serviceConfig ServiceConfig
    if err := json.Unmarshal(data, &serviceConfig); err != nil {
        logger.Printf("Failed to parse service config %s: %v", filename, err)
        return
    }

    // 设置默认值
    if serviceConfig.WorkDir == "" {
        serviceConfig.WorkDir = monitorConfig.Workspace
    }

    if serviceConfig.StdoutLog == "" {
        logDir := filepath.Join(serviceConfig.WorkDir, "log")
        os.MkdirAll(logDir, 0755)
        serviceConfig.StdoutLog = filepath.Join(logDir,
            filepath.Base(filename)+".stdout.log")
    }

    if serviceConfig.StderrLog == "" {
        logDir := filepath.Join(serviceConfig.WorkDir, "log")
        serviceConfig.StderrLog = filepath.Join(logDir,
            filepath.Base(filename)+".stderr.log")
    }

    if serviceConfig.MonitorMode == "" {
        serviceConfig.MonitorMode = "self"
    }

    if serviceConfig.CheckInterval <= 0 {
        serviceConfig.CheckInterval = DefaultCheckInterval
    }

    if serviceConfig.MaxFailures <= 0 {
        serviceConfig.MaxFailures = DefaultMaxFailures
    }

    // 验证必要字段
    if serviceConfig.StartCmd == "" || serviceConfig.PIDFile == "" {
        logger.Printf("Service config %s missing required fields", filename)
        return
    }

    // 创建服务状态
    serviceName := strings.TrimSuffix(filepath.Base(filename), "_service.json")
    serviceStatus := &ServiceStatus{
        Service:   &serviceConfig,
        IsRunning: false,
        FailCount: 0,
        LastCheck: time.Now(),
    }

    serviceMutex.Lock()
    services[serviceName] = serviceStatus
    serviceMutex.Unlock()

    logger.Printf("Loaded service config: %s", serviceName)
}

func startAllServices() {
    serviceMutex.RLock()
    serviceNames := make([]string, 0, len(services))
    for name := range services {
        serviceNames = append(serviceNames, name)
    }
    serviceMutex.RUnlock()

    // 按文件名排序启动
    sort.Strings(serviceNames)

    for _, name := range serviceNames {
        go startService(name)
    }
}

func startService(serviceName string) {
    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        return
    }

    status.mutex.Lock()
    defer status.mutex.Unlock()

    // 设置环境变量（不带MONITOR_前缀）
    env := os.Environ()
    env = append(env, fmt.Sprintf("WORKSPACE=%s", monitorConfig.Workspace))
    env = append(env, fmt.Sprintf("PROJECT_ID=%s", monitorConfig.ProjectID))
    env = append(env, fmt.Sprintf("SERVER_ADDR=%s", monitorConfig.ServerAddr))
    env = append(env, fmt.Sprintf("SERVER_PORT=%s", monitorConfig.ServerPort))
    env = append(env, fmt.Sprintf("UUID=%s", monitorConfig.UUID))
    env = append(env, fmt.Sprintf("LOG_LEVEL=%s", monitorConfig.LogLevel))
    env = append(env, fmt.Sprintf("LOG_PATH=%s", monitorConfig.LogPath))

    // 执行启动命令
    cmd := exec.Command("sh", "-c", status.Service.StartCmd)
    cmd.Env = env
    cmd.Dir = status.Service.WorkDir

    // 重定向标准输出和错误输出
    stdoutFile, err := os.OpenFile(status.Service.StdoutLog,
        os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        cmd.Stdout = stdoutFile
    }

    stderrFile, err := os.OpenFile(status.Service.StderrLog,
        os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        cmd.Stderr = stderrFile
    }

    // 根据监控模式处理PID文件
    if status.Service.MonitorMode == "monitor" {
        // 前台运行，由monitor写入PID
        if err := cmd.Start(); err != nil {
            logger.Printf("Failed to start service %s: %v", serviceName, err)
            return
        }

        pid := cmd.Process.Pid
        status.PID = pid
        status.Process = cmd.Process

        // 写入PID文件
        if err := os.WriteFile(status.Service.PIDFile,
            []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
            logger.Printf("Failed to write PID file for %s: %v", serviceName, err)
        }

        go func() {
            cmd.Wait()
            status.mutex.Lock()
            status.IsRunning = false
            status.mutex.Unlock()
            logger.Printf("Service %s exited", serviceName)
        }()
    } else {
        // 后台运行，服务自己写入PID
        if err := cmd.Start(); err != nil {
            logger.Printf("Failed to start service %s: %v", serviceName, err)
            return
        }

        // 等待服务写入PID文件
        time.Sleep(2 * time.Second)

        // 读取PID文件
        if pidData, err := os.ReadFile(status.Service.PIDFile); err == nil {
            var pid int
            fmt.Sscanf(string(pidData), "%d", &pid)
            status.PID = pid
        }
    }

    status.IsRunning = true
    status.StartTime = time.Now()
    logger.Printf("Service %s started", serviceName)
}

func checkServiceStatus() {
    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    for serviceName, status := range services {
        go func(name string, s *ServiceStatus) {
            s.mutex.Lock()
            defer s.mutex.Unlock()

            // 检查进程是否运行
            running := isProcessRunning(s.PID)

            if running {
                s.IsRunning = true
                s.FailCount = 0
            } else {
                s.FailCount++
                s.IsRunning = false

                // 检查是否达到最大失败次数
                if s.FailCount >= s.Service.MaxFailures {
                    logger.Printf("Service %s failed %d times, restarting", name, s.FailCount)
                    restartService(name)
                    s.FailCount = 0
                }
            }

            s.LastCheck = time.Now()
        }(serviceName, status)
    }
}

func isProcessRunning(pid int) bool {
    if pid <= 0 {
        return false
    }

    process, err := os.FindProcess(pid)
    if err != nil {
        return false
    }

    // 发送信号0来检查进程是否存在
    err = process.Signal(os.Signal(nil))
    return err == nil
}

func stopService(serviceName string) {
    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        return
    }

    status.mutex.Lock()
    defer status.mutex.Unlock()

    // 如果有停止命令，使用停止命令
    if status.Service.StopCmd != "" {
        cmd := exec.Command("sh", "-c", status.Service.StopCmd)
        cmd.Dir = status.Service.WorkDir
        if err := cmd.Run(); err != nil {
            logger.Printf("Failed to stop service %s with command: %v", serviceName, err)
        }
    } else {
        // 直接杀死进程
        if status.PID > 0 {
            process, err := os.FindProcess(status.PID)
            if err == nil {
                process.Kill()
            }
        }
    }

    status.IsRunning = false
    logger.Printf("Service %s stopped", serviceName)
}

func restartService(serviceName string) {
    logger.Printf("Restarting service %s", serviceName)

    stopService(serviceName)

    // 如果有重启命令，使用重启命令
    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        return
    }

    if status.Service.RestartCmd != "" {
        cmd := exec.Command("sh", "-c", status.Service.RestartCmd)
        cmd.Dir = status.Service.WorkDir

        // 设置环境变量（不带MONITOR_前缀）
        env := os.Environ()
        env = append(env, fmt.Sprintf("WORKSPACE=%s", monitorConfig.Workspace))
        env = append(env, fmt.Sprintf("PROJECT_ID=%s", monitorConfig.ProjectID))
        env = append(env, fmt.Sprintf("SERVER_ADDR=%s", monitorConfig.ServerAddr))
        env = append(env, fmt.Sprintf("SERVER_PORT=%s", monitorConfig.ServerPort))
        env = append(env, fmt.Sprintf("UUID=%s", monitorConfig.UUID))
        env = append(env, fmt.Sprintf("LOG_LEVEL=%s", monitorConfig.LogLevel))
        env = append(env, fmt.Sprintf("LOG_PATH=%s", monitorConfig.LogPath))
        cmd.Env = env

        if err := cmd.Start(); err != nil {
            logger.Printf("Failed to restart service %s: %v", serviceName, err)
            // 如果重启命令失败，尝试正常启动
            go startService(serviceName)
        }
    } else {
        // 正常重启流程
        go startService(serviceName)
    }
}

func startMonitorCron() {
    cronScheduler = cron.New()

    // 每10秒检查一次服务状态
    cronScheduler.AddFunc(fmt.Sprintf("@every %ds", DefaultCheckInterval), checkServiceStatus)

    cronScheduler.Start()
    logger.Println("Monitor cron scheduler started")
}

func keepAlive() {
    // 主循环，保持程序运行
    select {}
}