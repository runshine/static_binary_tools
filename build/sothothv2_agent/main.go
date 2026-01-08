package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "sync"
    "time"
    "strings"
    "sort"
    "encoding/json"
    "strconv"
    "io/ioutil"
    "syscall"
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
    EnableCgroup bool   `ini:"enable_cgroup"`
    CgroupName   string `ini:"cgroup_name"`
}

// 服务配置结构体
type ServiceConfig struct {
    Name         string   `json:"name"`
    StartCmd     string   `json:"start_cmd"`
    StopCmd      string   `json:"stop_cmd"`
    RestartCmd   string   `json:"restart_cmd"`
    PIDFile      string   `json:"pid_file"`
    StdoutLog    string   `json:"stdout_log"`
    StderrLog    string   `json:"stderr_log"`
    WorkDir      string   `json:"work_dir"`
    MonitorMode  string   `json:"monitor_mode"`
    CheckInterval int     `json:"check_interval"`
    MaxFailures  int      `json:"max_failures"`
    Description  string   `json:"description"`
    DependsOn    []string `json:"depends_on"`
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
    // 版本号使用日期格式：YYYYMMDD.HHMMSS
    BuildVersion = time.Now().Format("20060107.210405")

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
    enableCgroup = flag.Bool("enable-cgroup", true, "启用cgroup限制")
    cgroupName  = flag.String("cgroup-name", "sothothv2_agent", "cgroup名称")

    monitorConfig MonitorConfig
    services      map[string]*ServiceStatus
    serviceMutex  sync.RWMutex
    logger        *log.Logger
    cronScheduler *cron.Cron

    // 新增全局变量
    serviceStartOrder []string          // 服务启动顺序
    isShuttingDown    bool              // 是否正在关闭
    shutdownMutex     sync.RWMutex      // 关闭状态锁
    shutdownWG        sync.WaitGroup    // 等待所有服务关闭
    signalChan        chan os.Signal    // 信号通道
)

const (
    DefaultCheckInterval = 10
    DefaultMaxFailures = 6
    ServiceStopTimeout = 10 * time.Second  // 修改为10秒
)

func init() {
    // 初始化日志
    logger = log.New(os.Stdout, fmt.Sprintf("[SothothV2 %s] ", BuildVersion), log.LstdFlags|log.Lshortfile)

    // 初始化信号通道
    signalChan = make(chan os.Signal, 1)
}

func main() {
    flag.Parse()

    if *versionFlag {
        fmt.Printf("SothothV2 Monitor Agent Version: %s\n", BuildVersion)
        fmt.Printf("Build Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
        return
    }

    // 检查配置文件是否存在
    if _, err := os.Stat(*configFile); err == nil {
        loadConfigFromFile(*configFile)
    } else {
        loadConfigFromFlags()
        saveConfigToFile(*configFile)
    }

    logger.Printf("Starting SothothV2 Agent v%s", BuildVersion)

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

    // 检查并创建cgroup
    if monitorConfig.EnableCgroup {
        initCgroup()
    }

    // 设置信号处理
    setupSignalHandler()

    // 如果不是前台运行，则作为守护进程运行
    if !monitorConfig.Foreground && os.Getppid() != 1 {
        daemonize()
        return
    }

    logger.Printf("Agent started. UUID: %s", monitorConfig.UUID)
    logger.Printf("Workspace: %s", monitorConfig.Workspace)
    logger.Printf("Project ID: %s", monitorConfig.ProjectID)
    logger.Printf("Server: %s:%s", monitorConfig.ServerAddr, monitorConfig.ServerPort)
    logger.Printf("Signal handler installed. Send SIGINT or SIGTERM for graceful shutdown.")
    logger.Printf("Service stop timeout: %v", ServiceStopTimeout)

    // 初始化服务
    services = make(map[string]*ServiceStatus)
    serviceStartOrder = make([]string, 0)

    // 创建service_config目录
    serviceConfigDir := filepath.Join(monitorConfig.Workspace, "service_config")
    if err := os.MkdirAll(serviceConfigDir, 0755); err != nil {
        logger.Printf("Failed to create service config directory: %v", err)
    }

    // 加载服务配置并输出详细信息
    loadServiceConfigs(serviceConfigDir)

    // 启动cron定时任务
    startMonitorCron()

    // 启动所有服务
    startAllServices()

    // 等待关闭信号
    waitForShutdown()
}

// 设置信号处理器
func setupSignalHandler() {
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

    // 启动信号处理goroutine
    go func() {
        for sig := range signalChan {
            switch sig {
            case syscall.SIGINT, syscall.SIGTERM:
                logger.Printf("Received shutdown signal: %v", sig)
                gracefulShutdown()
            case syscall.SIGHUP:
                logger.Printf("Received SIGHUP, reloading configuration...")
                // 这里可以添加重新加载配置的逻辑
            }
        }
    }()
}

// 优雅关闭
func gracefulShutdown() {
    shutdownMutex.Lock()
    if isShuttingDown {
        shutdownMutex.Unlock()
        logger.Println("Shutdown already in progress...")
        return
    }
    isShuttingDown = true
    shutdownMutex.Unlock()

    shutdownStartTime := time.Now()
    logger.Println("========== Starting Graceful Shutdown ==========")
    logger.Printf("Shutdown initiated at: %s", shutdownStartTime.Format("2006-01-02 15:04:05"))

    // 停止监控调度器
    stopMonitorCron()

    // 按照启动顺序的反顺序关闭所有服务
    stopAllServices()

    // 等待所有服务关闭完成
    logger.Println("Waiting for all services to stop...")
    shutdownWG.Wait()

    // 显示统计信息
    printShutdownStatistics(shutdownStartTime)

    // 清理cgroup
    if monitorConfig.EnableCgroup {
        cleanupCgroup()
    }

    logger.Println("========== All Services Stopped, Monitor Exiting ==========")
    logger.Printf("Total shutdown time: %v", time.Since(shutdownStartTime))

    // 延迟1秒确保日志写入
    time.Sleep(1 * time.Second)
    os.Exit(0)
}

// 停止监控调度器
func stopMonitorCron() {
    if cronScheduler != nil {
        logger.Println("Stopping monitor cron scheduler...")
        cronScheduler.Stop()
        logger.Println("✓ Cron scheduler stopped")
    }
}

// 停止所有服务
func stopAllServices() {
    serviceMutex.RLock()
    totalServices := len(services)
    serviceMutex.RUnlock()

    logger.Printf("Stopping %d service(s) in reverse startup order", totalServices)

    // 反转启动顺序
    reverseOrder := make([]string, len(serviceStartOrder))
    for i, j := 0, len(serviceStartOrder)-1; i < len(serviceStartOrder); i, j = i+1, j-1 {
        reverseOrder[i] = serviceStartOrder[j]
    }

    logger.Printf("Shutdown order: %v", reverseOrder)
    logger.Printf("Each service timeout: %v", ServiceStopTimeout)

    // 并发停止所有服务，但每个服务有自己的超时控制
    for _, serviceName := range reverseOrder {
        shutdownWG.Add(1)
        go func(name string) {
            defer shutdownWG.Done()
            stopServiceWithTimeout(name)
        }(serviceName)
    }
}

// 带超时的停止服务
func stopServiceWithTimeout(serviceName string) {
    logger.Printf("[%s] Starting shutdown process (timeout: %v)", serviceName, ServiceStopTimeout)

    // 创建超时上下文
    timeoutChan := time.After(ServiceStopTimeout)
    doneChan := make(chan bool, 1)
    forceKilledChan := make(chan bool, 1)

    // 启动停止goroutine
    go func() {
        stopService(serviceName)
        doneChan <- true
    }()

    // 等待停止完成或超时
    select {
    case <-doneChan:
        logger.Printf("[%s] ✓ Shutdown completed normally", serviceName)
    case <-timeoutChan:
        logger.Printf("[%s] ⚠ Shutdown timeout after %v, forcing kill...", serviceName, ServiceStopTimeout)
        forceKillService(serviceName)
        forceKilledChan <- true
    }

    // 等待强制杀死完成
    select {
    case <-forceKilledChan:
        logger.Printf("[%s] ✗ Service force killed after timeout", serviceName)
    default:
        // 正常关闭，不需要处理
    }
}

// 停止单个服务
// 停止单个服务
func stopService(serviceName string) bool {
    startTime := time.Now()
    logger.Printf("[%s] Stopping service...", serviceName)

    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        logger.Printf("[%s] Service not found", serviceName)
        return false
    }

    status.mutex.Lock()
    defer status.mutex.Unlock()

    // 如果服务已经停止，直接返回
    if !status.IsRunning {
        logger.Printf("[%s] Service already stopped", serviceName)
        return true
    }

    // 记录停止前的状态
    originalPID := status.PID
    logger.Printf("[%s] Current PID: %d", serviceName, originalPID)

    // 创建一个通道用于控制停止命令的执行
    stopDone := make(chan bool, 1)

    // 如果有停止命令，使用停止命令
    if status.Service.StopCmd != "" {
        logger.Printf("[%s] Using stop command: %s", serviceName, status.Service.StopCmd)

        go func() {
            cmd := exec.Command("sh", "-c", status.Service.StopCmd)
            cmd.Dir = status.Service.WorkDir

            // 设置超时
            cmd.Stdout = os.Stdout
            cmd.Stderr = os.Stderr

            if err := cmd.Start(); err != nil {
                logger.Printf("[%s] Failed to start stop command: %v", serviceName, err)
                stopDone <- false
                return
            }

            // 等待命令完成，最多等待5秒
            timeout := 5 * time.Second
            done := make(chan error, 1)
            go func() {
                done <- cmd.Wait()
            }()

            select {
            case err := <-done:
                if err != nil {
                    logger.Printf("[%s] Stop command completed with error: %v", serviceName, err)
                } else {
                    logger.Printf("[%s] Stop command completed successfully", serviceName)
                }
                stopDone <- true
            case <-time.After(timeout):
                logger.Printf("[%s] Stop command timeout after %v, killing...", serviceName, timeout)
                cmd.Process.Kill()
                stopDone <- false
            }
        }()

        // 等待停止命令完成
        select {
        case success := <-stopDone:
            if !success {
                logger.Printf("[%s] Stop command failed, proceeding to kill", serviceName)
            }
        case <-time.After(6 * time.Second):
            logger.Printf("[%s] Stop command timed out, proceeding to kill", serviceName)
        }
    }

    // 直接杀死进程（无论是否有停止命令或停止命令是否成功）
    killSuccess := false
    if status.PID > 0 {
        logger.Printf("[%s] Sending SIGTERM to PID %d", serviceName, status.PID)

        process, err := os.FindProcess(status.PID)
        if err != nil {
            logger.Printf("[%s] Failed to find process: %v", serviceName, err)
        } else {
            // 先发送SIGTERM
            if err := process.Signal(syscall.SIGTERM); err != nil {
                logger.Printf("[%s] Failed to send SIGTERM: %v", serviceName, err)
            } else {
                // 等待进程退出，最多等待3秒
                for i := 0; i < 3; i++ {
                    if !isProcessRunning(status.PID) {
                        killSuccess = true
                        break
                    }
                    time.Sleep(1 * time.Second)
                }
            }

            // 如果SIGTERM失败，尝试SIGKILL
            if !killSuccess {
                logger.Printf("[%s] Process still running, sending SIGKILL", serviceName)
                if err := process.Kill(); err != nil {
                    logger.Printf("[%s] Failed to kill process: %v", serviceName, err)
                } else {
                    killSuccess = true
                }
            }
        }
    }

    // 清理PID文件
    if _, err := os.Stat(status.Service.PIDFile); err == nil {
        if err := os.Remove(status.Service.PIDFile); err != nil {
            logger.Printf("[%s] Failed to remove PID file: %v", serviceName, err)
        } else {
            logger.Printf("[%s] Removed PID file: %s", serviceName, status.Service.PIDFile)
        }
    }

    status.IsRunning = false
    status.PID = 0

    shutdownTime := time.Since(startTime)
    if killSuccess || originalPID <= 0 {
        logger.Printf("[%s] ✓ Service stopped (took %v)", serviceName, shutdownTime)
        return true
    } else {
        logger.Printf("[%s] ⚠ Service may not have stopped cleanly (took %v)", serviceName, shutdownTime)
        return false
    }
}

// 强制杀死服务
func forceKillService(serviceName string) {
    logger.Printf("[%s] FORCE KILLING SERVICE", serviceName)

    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        return
    }

    status.mutex.Lock()
    defer status.mutex.Unlock()

    if status.PID > 0 {
        process, err := os.FindProcess(status.PID)
        if err == nil {
            // 先尝试SIGKILL
            if err := process.Kill(); err != nil {
                logger.Printf("[%s] Failed to SIGKILL process: %v", serviceName, err)
            } else {
                logger.Printf("[%s] Sent SIGKILL to PID %d", serviceName, status.PID)
            }
        }

        // 双保险：使用系统kill命令
        cmd := exec.Command("kill", "-9", strconv.Itoa(status.PID))
        cmd.Run()
    }

    // 强制移除PID文件
    if _, err := os.Stat(status.Service.PIDFile); err == nil {
        os.Remove(status.Service.PIDFile)
    }

    status.IsRunning = false
    status.PID = 0
    logger.Printf("[%s] ✗ Service force killed", serviceName)
}

// 打印关闭统计信息
func printShutdownStatistics(startTime time.Time) {
    logger.Println("========== Shutdown Statistics ==========")
    logger.Printf("Shutdown start time: %s", startTime.Format("2006-01-02 15:04:05"))
    logger.Printf("Shutdown end time: %s", time.Now().Format("2006-01-02 15:04:05"))
    logger.Printf("Total shutdown duration: %v", time.Since(startTime))
    logger.Printf("Total services: %d", len(services))

    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    stoppedCount := 0
    runningCount := 0
    for _, status := range services {
        status.mutex.RLock()
        if status.IsRunning {
            runningCount++
        } else {
            stoppedCount++
        }
        status.mutex.RUnlock()
    }

    logger.Printf("Services successfully stopped: %d", stoppedCount)
    logger.Printf("Services still running (failed to stop): %d", runningCount)

    if runningCount > 0 {
        logger.Println("Warning: Some services may not have been stopped cleanly!")
    }

    logger.Println("=========================================")
}

// 初始化cgroup
func initCgroup() {
    logger.Println("Checking cgroup support...")

    if _, err := os.Stat("/sys/fs/cgroup"); os.IsNotExist(err) {
        logger.Println("Cgroup not supported or not mounted at /sys/fs/cgroup")
        return
    }

    cgroupPath := filepath.Join("/sys/fs/cgroup", monitorConfig.CgroupName)
    if err := os.MkdirAll(cgroupPath, 0755); err != nil {
        logger.Printf("Failed to create cgroup directory: %v", err)
        return
    }

    pid := os.Getpid()
    pidFile := filepath.Join(cgroupPath, "cgroup.procs")
    if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
        logger.Printf("Failed to add process to cgroup: %v", err)
        return
    }

    logger.Printf("Successfully created and joined cgroup: %s", cgroupPath)
    logger.Printf("Current process PID %d is now in cgroup", pid)
}

// 清理cgroup
func cleanupCgroup() {
    if !monitorConfig.EnableCgroup {
        return
    }

    cgroupPath := filepath.Join("/sys/fs/cgroup", monitorConfig.CgroupName)

    // 首先将当前进程移出cgroup（移到根cgroup）
    pid := os.Getpid()
    rootCgroupFile := "/sys/fs/cgroup/cgroup.procs"
    if _, err := os.Stat(rootCgroupFile); err == nil {
        ioutil.WriteFile(rootCgroupFile, []byte(strconv.Itoa(pid)), 0644)
    }

    // 尝试删除cgroup目录
    time.Sleep(100 * time.Millisecond) // 等待进程移出

    // 递归删除cgroup目录
    if err := os.RemoveAll(cgroupPath); err != nil {
        logger.Printf("Failed to remove cgroup directory: %v", err)
    } else {
        logger.Printf("✓ Cgroup cleaned up: %s", cgroupPath)
    }
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
    monitorConfig.EnableCgroup = *enableCgroup
    monitorConfig.CgroupName = *cgroupName
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
    cmd := exec.Command(os.Args[0], os.Args[1:]...)
    cmd.Env = os.Environ()

    if err := cmd.Start(); err != nil {
        logger.Fatalf("Failed to start daemon: %v", err)
    }

    fmt.Printf("Daemon started with PID: %d\n", cmd.Process.Pid)
    os.Exit(0)
}

func loadServiceConfigs(configDir string) {
    logger.Printf("========== Loading Service Configurations ==========")

    pattern := filepath.Join(configDir, "*_service.json")
    files, err := filepath.Glob(pattern)
    if err != nil {
        logger.Printf("Failed to find service config files: %v", err)
        return
    }

    if len(files) == 0 {
        logger.Println("No service configuration files found")
        return
    }

    logger.Printf("Found %d service configuration file(s)", len(files))

    sort.Strings(files)

    for i, file := range files {
        logger.Printf("\n[%d/%d] Loading: %s", i+1, len(files), filepath.Base(file))
        loadServiceConfig(file)
    }

    logger.Printf("========== Service Configuration Summary ==========")
    logger.Printf("Total services loaded: %d", len(services))
    logger.Printf("Startup order: %v", serviceStartOrder)
    logger.Println("=================================================")
}

func loadServiceConfig(filename string) {
    data, err := ioutil.ReadFile(filename)
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

    if serviceConfig.Description == "" {
        serviceConfig.Description = fmt.Sprintf("Service defined in %s", filepath.Base(filename))
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

    // 记录启动顺序
    serviceStartOrder = append(serviceStartOrder, serviceName)

    logger.Printf("✓ Successfully loaded: %s", serviceName)
}

func startAllServices() {
    logger.Println("========== Starting All Services ==========")

    logger.Printf("Starting %d service(s) in order: %v", len(serviceStartOrder), serviceStartOrder)

    for _, name := range serviceStartOrder {
        go startService(name)
        time.Sleep(1 * time.Second)
    }

    logger.Println("==========================================")
}

func startService(serviceName string) {
    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        return
    }

    logger.Printf("[%s] Starting service...", serviceName)

    status.mutex.Lock()
    defer status.mutex.Unlock()

    // 检查是否正在关闭
    shutdownMutex.RLock()
    if isShuttingDown {
        shutdownMutex.RUnlock()
        logger.Printf("[%s] Skipping start (shutdown in progress)", serviceName)
        return
    }
    shutdownMutex.RUnlock()

    // 检查依赖的服务是否已启动
    if len(status.Service.DependsOn) > 0 {
        logger.Printf("[%s] Checking dependencies: %v", serviceName, status.Service.DependsOn)
        for _, dep := range status.Service.DependsOn {
            if depStatus, ok := services[dep]; ok && depStatus.IsRunning {
                logger.Printf("[%s] ✓ Dependency satisfied: %s", serviceName, dep)
            }
        }
    }

    // 设置环境变量
    env := os.Environ()
    env = append(env, fmt.Sprintf("WORKSPACE=%s", monitorConfig.Workspace))
    env = append(env, fmt.Sprintf("PROJECT_ID=%s", monitorConfig.ProjectID))
    env = append(env, fmt.Sprintf("SERVER_ADDR=%s", monitorConfig.ServerAddr))
    env = append(env, fmt.Sprintf("SERVER_PORT=%s", monitorConfig.ServerPort))
    env = append(env, fmt.Sprintf("UUID=%s", monitorConfig.UUID))
    env = append(env, fmt.Sprintf("LOG_LEVEL=%s", monitorConfig.LogLevel))
    env = append(env, fmt.Sprintf("LOG_PATH=%s", monitorConfig.LogPath))
    env = append(env, fmt.Sprintf("BUILD_VERSION=%s", BuildVersion))

    // 执行启动命令
    cmd := exec.Command("sh", "-c", status.Service.StartCmd)
    cmd.Env = env
    cmd.Dir = status.Service.WorkDir

    // 重定向标准输出和错误输出
    stdoutFile, err := os.OpenFile(status.Service.StdoutLog,
        os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        cmd.Stdout = stdoutFile
        logger.Printf("[%s] Stdout log: %s", serviceName, status.Service.StdoutLog)
    }

    stderrFile, err := os.OpenFile(status.Service.StderrLog,
        os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        cmd.Stderr = stderrFile
        logger.Printf("[%s] Stderr log: %s", serviceName, status.Service.StderrLog)
    }

    logger.Printf("[%s] Working directory: %s", serviceName, status.Service.WorkDir)
    logger.Printf("[%s] Monitor mode: %s", serviceName, status.Service.MonitorMode)

    // 根据监控模式处理PID文件
    // 在monitor模式下，修改goroutine部分：
    if status.Service.MonitorMode == "monitor" {
        logger.Printf("[%s] Running in foreground (monitor mode)", serviceName)
        if err := cmd.Start(); err != nil {
            logger.Printf("[%s] Failed to start service: %v", serviceName, err)
            return
        }

        pid := cmd.Process.Pid
        status.PID = pid
        status.Process = cmd.Process

        // 写入PID文件
        if err := ioutil.WriteFile(status.Service.PIDFile,
            []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
            logger.Printf("[%s] Failed to write PID file: %v", serviceName, err)
        } else {
            logger.Printf("[%s] PID written to: %s", serviceName, status.Service.PIDFile)
        }

        // 创建一个通道来控制goroutine的退出
        processExitChan := make(chan bool, 1)

        go func() {
            cmd.Wait()
            processExitChan <- true

            status.mutex.Lock()
            status.IsRunning = false
            status.mutex.Unlock()

            // 检查是否正在关闭
            shutdownMutex.RLock()
            if !isShuttingDown {
                shutdownMutex.RUnlock()
                logger.Printf("[%s] Service exited unexpectedly, will restart in 5 seconds", serviceName)
                time.Sleep(5 * time.Second)
                // 使用新的goroutine重启，避免阻塞
                go startService(serviceName)
            } else {
                shutdownMutex.RUnlock()
                logger.Printf("[%s] Service exited during shutdown", serviceName)
            }
        }()

        // 设置一个超时监控goroutine
        go func() {
            select {
            case <-processExitChan:
                // 正常退出
            case <-time.After(30 * time.Second):
                // 30秒后如果goroutine还在，记录警告
                logger.Printf("[%s] Warning: process monitoring goroutine still running after 30s", serviceName)
            }
        }()
    } else {
        logger.Printf("[%s] Running in background (self mode)", serviceName)
        if err := cmd.Start(); err != nil {
            logger.Printf("[%s] Failed to start service: %v", serviceName, err)
            return
        }

        // 等待服务写入PID文件
        logger.Printf("[%s] Waiting for PID file: %s", serviceName, status.Service.PIDFile)
        for i := 0; i < 5; i++ {
            time.Sleep(1 * time.Second)
            if pidData, err := ioutil.ReadFile(status.Service.PIDFile); err == nil {
                var pid int
                fmt.Sscanf(string(pidData), "%d", &pid)
                status.PID = pid
                logger.Printf("[%s] Got PID from file: %d", serviceName, pid)
                break
            }
        }
    }

    status.IsRunning = true
    status.StartTime = time.Now()
    logger.Printf("[%s] ✓ Service started successfully", serviceName)
}

func checkServiceStatus() {
    // 检查是否正在关闭
    shutdownMutex.RLock()
    if isShuttingDown {
        shutdownMutex.RUnlock()
        return
    }
    shutdownMutex.RUnlock()

    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    for serviceName, status := range services {
        go func(name string, s *ServiceStatus) {
            s.mutex.Lock()

            // 检查是否正在关闭
            shutdownMutex.RLock()
            if isShuttingDown {
                shutdownMutex.RUnlock()
                s.mutex.Unlock()
                return
            }
            shutdownMutex.RUnlock()

            // 检查进程是否运行
            running := isProcessRunning(s.PID)

            if running {
                if !s.IsRunning {
                    logger.Printf("[%s] Service recovered", name)
                }
                s.IsRunning = true
                s.FailCount = 0
                s.LastCheck = time.Now()
                s.mutex.Unlock()
            } else {
                s.FailCount++
                s.IsRunning = false

                logger.Printf("[%s] Service not running (fail count: %d/%d)",
                    name, s.FailCount, s.Service.MaxFailures)

                // 检查是否达到最大失败次数
                if s.FailCount >= s.Service.MaxFailures {
                    // 释放锁后再重启，避免死锁
                    s.mutex.Unlock()
                    logger.Printf("[%s] Max failures reached, restarting...", name)
                    go restartService(name) // 使用goroutine避免阻塞
                } else {
                    s.LastCheck = time.Now()
                    s.mutex.Unlock()
                }
            }
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

    err = process.Signal(syscall.Signal(0))
    return err == nil
}

// 检查服务状态详情
func debugServiceStatus(serviceName string) {
    serviceMutex.RLock()
    status, exists := services[serviceName]
    serviceMutex.RUnlock()

    if !exists {
        logger.Printf("[DEBUG] Service %s not found", serviceName)
        return
    }

    status.mutex.RLock()
    defer status.mutex.RUnlock()

    logger.Printf("[DEBUG] Service: %s", serviceName)
    logger.Printf("[DEBUG]   IsRunning: %v", status.IsRunning)
    logger.Printf("[DEBUG]   PID: %d", status.PID)
    logger.Printf("[DEBUG]   FailCount: %d/%d", status.FailCount, status.Service.MaxFailures)
    logger.Printf("[DEBUG]   LastCheck: %v", time.Since(status.LastCheck))
    logger.Printf("[DEBUG]   MonitorMode: %s", status.Service.MonitorMode)

    // 检查进程是否存在
    if status.PID > 0 {
        running := isProcessRunning(status.PID)
        logger.Printf("[DEBUG]   Process running: %v", running)

        // 检查PID文件是否存在
        if _, err := os.Stat(status.Service.PIDFile); err == nil {
            data, err := ioutil.ReadFile(status.Service.PIDFile)
            if err == nil {
                logger.Printf("[DEBUG]   PID file content: %s", string(data))
            }
        }
    }
}

func restartService(serviceName string) {
    logger.Printf("[%s] === Restarting Service ===", serviceName)

    // 快速停止服务，不等待太长时间
    stopSuccess := stopService(serviceName)

    if stopSuccess {
        // 等待1秒
        time.Sleep(1 * time.Second)
    } else {
        // 如果停止失败，等待更短时间
        logger.Printf("[%s] Stop failed, waiting 500ms before restart", serviceName)
        time.Sleep(500 * time.Millisecond)
    }

    // 检查是否正在关闭
    shutdownMutex.RLock()
    if isShuttingDown {
        shutdownMutex.RUnlock()
        logger.Printf("[%s] Skipping restart (shutdown in progress)", serviceName)
        return
    }
    shutdownMutex.RUnlock()

    // 重新启动服务
    go startService(serviceName)

    logger.Printf("[%s] === Restart Initiated ===", serviceName)
}

func startMonitorCron() {
    cronScheduler = cron.New()

    // 每10秒检查一次服务状态
    cronScheduler.AddFunc("@every 10s", func() {
        checkServiceStatus()
    })

    // 每小时打印一次状态报告
    cronScheduler.AddFunc("@hourly", func() {
        printStatusReport()
    })

    cronScheduler.Start()
    logger.Println("Monitor cron scheduler started")
}

func printStatusReport() {
    // 检查是否正在关闭
    shutdownMutex.RLock()
    if isShuttingDown {
        shutdownMutex.RUnlock()
        return
    }
    shutdownMutex.RUnlock()

    logger.Println("========== Status Report ==========")
    logger.Printf("Agent Version: %s", BuildVersion)
    logger.Printf("Agent UUID: %s", monitorConfig.UUID)
    logger.Printf("Uptime: %s", time.Now().Format("2006-01-02 15:04:05"))
    logger.Printf("Total services: %d", len(services))

    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    runningCount := 0
    for _, status := range services {
        status.mutex.RLock()
        if status.IsRunning {
            runningCount++
        }
        status.mutex.RUnlock()
    }

    logger.Printf("Services running: %d/%d", runningCount, len(services))
    logger.Println("==================================")
}

func waitForShutdown() {
    logger.Println("Agent is now running. Press Ctrl+C or send SIGTERM for graceful shutdown.")

    // 阻塞主线程，等待信号
    select {}
}