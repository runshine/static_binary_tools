package main

import (
    "compress/gzip"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/google/uuid"
    "github.com/robfig/cron/v3"
    "gopkg.in/ini.v1"
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
    Shell        bool     `json:"shell"` // 新增：是否使用shell启动，默认true
}

// 服务运行状态
type ServiceStatus struct {
    Service     *ServiceConfig
    Process     *os.Process
    Cmd         *exec.Cmd        // 新增：保存cmd引用
    PID         int
    StartTime   time.Time
    FailCount   int
    IsRunning   bool
    LastCheck   time.Time
    mutex       sync.RWMutex
}

// RotateConfig 日志轮转配置
type RotateConfig struct {
    MaxSize        int64  // 最大文件大小（字节）
    MaxBackups     int    // 最大备份文件数量
    Compress       bool   // 是否压缩旧日志
    CompressSuffix string // 压缩文件后缀
}

// 全局变量
var (
    // 版本号使用日期格式：YYYYMMDD.HHMMSS
    BuildVersion = time.Now().Format("20060102.150405")

    // 命令行参数
    configFile   = flag.String("config", "monitor.ini", "配置文件路径")
    workspace    = flag.String("workspace", "", "工作空间目录")
    projectID    = flag.String("project-id", "", "项目ID")
    serverAddr   = flag.String("server-addr", "", "服务器地址")
    serverPort   = flag.String("server-port", "", "服务器端口")
    uuidFlag     = flag.String("uuid", "", "Agent UUID")
    logLevel     = flag.String("log-level", "info", "日志级别")
    logPath      = flag.String("log-path", "", "日志目录")
    foreground   = flag.Bool("foreground", false, "在前台运行")
    versionFlag  = flag.Bool("version", false, "显示版本信息")
    enableCgroup = flag.Bool("enable-cgroup", true, "启用cgroup限制")
    cgroupName   = flag.String("cgroup-name", "sothothv2_agent", "cgroup名称")

    // 默认轮转配置
    DefaultRotateConfig = RotateConfig{
        MaxSize:        5 * 1024 * 1024, // 5MB
        MaxBackups:     2,               // 保留2个压缩文件
        Compress:       true,
        CompressSuffix: ".gz",
    }

    // 配置和状态
    monitorConfig MonitorConfig
    services      map[string]*ServiceStatus
    serviceMutex  sync.RWMutex
    logger        *log.Logger
    cronScheduler *cron.Cron

    // 关闭控制
    serviceStartOrder []string          // 服务启动顺序
    isShuttingDown    bool              // 是否正在关闭
    shutdownMutex     sync.RWMutex      // 关闭状态锁
    shutdownWG        sync.WaitGroup    // 等待所有服务关闭
    signalChan        chan os.Signal    // 信号通道

    // 新增：进程互斥锁相关
    lockFile     *os.File
    lockFilePath string
)

const (
    DefaultCheckInterval = 10
    DefaultMaxFailures = 6
    ServiceStopTimeout = 10 * time.Second  // 服务停止超时时间
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

    // 新增：创建并获取进程锁，防止重复拉起
    if err := acquireProcessLock(); err != nil {
        logger.Fatalf("Failed to acquire process lock: %v", err)
    }
    defer releaseProcessLock()

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

    // 清理过多的备份文件
    cleanupExcessiveBackups()

    // 启动cron定时任务
    startMonitorCron()

    // 启动所有服务
    startAllServices()

    // 等待关闭信号
    waitForShutdown()
}

// ==================== 日志轮转功能 ====================

// RotateLogFile 轮转日志文件
func RotateLogFile(filename string, config RotateConfig) error {
    // 检查文件是否存在
    if _, err := os.Stat(filename); os.IsNotExist(err) {
        return nil // 文件不存在，无需轮转
    }

    // 检查文件大小
    info, err := os.Stat(filename)
    if err != nil {
        return fmt.Errorf("failed to stat log file: %v", err)
    }

    // 如果文件小于最大大小，不轮转
    if info.Size() < config.MaxSize {
        return nil
    }

    // 生成时间戳
    timestamp := time.Now().Format("20060102-150405")

    // 构建备份文件名
    baseDir := filepath.Dir(filename)
    baseName := filepath.Base(filename)
    backupName := fmt.Sprintf("%s.%s", baseName, timestamp)

    var backupPath string
    if config.Compress {
        backupPath = filepath.Join(baseDir, backupName+config.CompressSuffix)
    } else {
        backupPath = filepath.Join(baseDir, backupName)
    }

    // 创建备份文件
    if config.Compress {
        if err := compressFile(filename, backupPath); err != nil {
            return fmt.Errorf("failed to compress log file: %v", err)
        }
    } else {
        if err := os.Rename(filename, backupPath); err != nil {
            return fmt.Errorf("failed to rename log file: %v", err)
        }
    }

    // 清理旧的备份文件
    if err := cleanupOldBackups(baseDir, baseName, config); err != nil {
        logger.Printf("Failed to cleanup old backups: %v", err)
    }

    // 创建新的日志文件
    file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        return fmt.Errorf("failed to create new log file: %v", err)
    }
    file.Close()

    logger.Printf("Rotated log file: %s -> %s", filename, filepath.Base(backupPath))
    return nil
}

// compressFile 压缩文件
func compressFile(src, dst string) error {
    // 打开源文件
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    // 创建目标文件
    dstFile, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer dstFile.Close()

    // 创建gzip writer
    gzWriter := gzip.NewWriter(dstFile)
    defer gzWriter.Close()

    // 复制数据
    if _, err := io.Copy(gzWriter, srcFile); err != nil {
        return err
    }

    // 关闭gzip writer以确保所有数据写入
    if err := gzWriter.Close(); err != nil {
        return err
    }

    // 删除源文件
    if err := os.Remove(src); err != nil {
        return err
    }

    return nil
}

// cleanupOldBackups 清理旧的备份文件
func cleanupOldBackups(dir, baseName string, config RotateConfig) error {
    pattern := fmt.Sprintf("%s.*", baseName)
    if config.Compress {
        pattern += config.CompressSuffix
    }

    files, err := filepath.Glob(filepath.Join(dir, pattern))
    if err != nil {
        return err
    }

    // 如果文件数量不超过最大备份数量，直接返回
    if len(files) <= config.MaxBackups {
        return nil
    }

    // 按修改时间排序（从旧到新）
    sort.Slice(files, func(i, j int) bool {
        info1, _ := os.Stat(files[i])
        info2, _ := os.Stat(files[j])
        return info1.ModTime().Before(info2.ModTime())
    })

    // 删除最旧的文件，直到数量符合要求
    for i := 0; i < len(files)-config.MaxBackups; i++ {
        if err := os.Remove(files[i]); err != nil {
            logger.Printf("Failed to remove old backup %s: %v", files[i], err)
        } else {
            logger.Printf("Removed old backup: %s", filepath.Base(files[i]))
        }
    }

    return nil
}

// openLogFileWithRotation 打开日志文件并检查是否需要轮转
func openLogFileWithRotation(filename string, config RotateConfig) (*os.File, error) {
    // 确保目录存在
    dir := filepath.Dir(filename)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create log directory: %v", err)
    }

    // 检查是否需要轮转
    if err := RotateLogFile(filename, config); err != nil {
        logger.Printf("Failed to rotate log file %s: %v", filename, err)
    }

    // 打开日志文件
    return os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
}

// setupLoggerWithRotation 设置带轮转的日志
func setupLoggerWithRotation() {
    if monitorConfig.LogPath != "" {
        logFile := filepath.Join(monitorConfig.LogPath, "monitor.log")

        // 使用带轮转的日志文件打开
        file, err := openLogFileWithRotation(logFile, DefaultRotateConfig)
        if err == nil {
            logger.SetOutput(file)
            logger.Printf("Monitor log file with rotation enabled: %s", logFile)
        } else {
            logger.Printf("Failed to open log file: %v", err)
        }
    }
}

// rotateAllServiceLogs 轮转所有服务的日志文件
func rotateAllServiceLogs() {
    logger.Println("Checking service log files for rotation...")

    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    for serviceName, status := range services {
        status.mutex.RLock()

        // 轮转标准输出日志
        if status.Service.StdoutLog != "" {
            if err := RotateLogFile(status.Service.StdoutLog, DefaultRotateConfig); err != nil {
                logger.Printf("[%s] Failed to rotate stdout log: %v", serviceName, err)
            }
        }

        // 轮转标准错误日志
        if status.Service.StderrLog != "" {
            if err := RotateLogFile(status.Service.StderrLog, DefaultRotateConfig); err != nil {
                logger.Printf("[%s] Failed to rotate stderr log: %v", serviceName, err)
            }
        }

        status.mutex.RUnlock()
    }

    // 轮转监控器自身的日志
    if monitorConfig.LogPath != "" {
        logFile := filepath.Join(monitorConfig.LogPath, "monitor.log")
        if err := RotateLogFile(logFile, DefaultRotateConfig); err != nil {
            logger.Printf("Failed to rotate monitor log: %v", err)
        }
    }
}

// cleanupExcessiveBackups 清理过多的备份文件
func cleanupExcessiveBackups() {
    logger.Println("Cleaning up excessive log backups...")

    // 检查监控器日志备份
    if monitorConfig.LogPath != "" {
        logFile := filepath.Join(monitorConfig.LogPath, "monitor.log")
        dir := filepath.Dir(logFile)
        baseName := filepath.Base(logFile)
        if err := cleanupOldBackups(dir, baseName, DefaultRotateConfig); err != nil {
            logger.Printf("Failed to cleanup monitor log backups: %v", err)
        }
    }

    // 检查服务日志备份
    serviceMutex.RLock()
    defer serviceMutex.RUnlock()

    for serviceName, status := range services {
        status.mutex.RLock()

        // 清理stdout日志备份
        if status.Service.StdoutLog != "" {
            dir := filepath.Dir(status.Service.StdoutLog)
            baseName := filepath.Base(status.Service.StdoutLog)
            if err := cleanupOldBackups(dir, baseName, DefaultRotateConfig); err != nil {
                logger.Printf("[%s] Failed to cleanup stdout log backups: %v", serviceName, err)
            }
        }

        // 清理stderr日志备份
        if status.Service.StderrLog != "" {
            dir := filepath.Dir(status.Service.StderrLog)
            baseName := filepath.Base(status.Service.StderrLog)
            if err := cleanupOldBackups(dir, baseName, DefaultRotateConfig); err != nil {
                logger.Printf("[%s] Failed to cleanup stderr log backups: %v", serviceName, err)
            }
        }

        status.mutex.RUnlock()
    }
}

// ==================== 信号处理和优雅关闭 ====================

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

// ==================== 进程管理 ====================

// 获取进程的所有子进程
func getChildProcesses(pid int) ([]int, error) {
    childPids := []int{}

    // 遍历/proc目录查找子进程
    procDir := "/proc"
    entries, err := ioutil.ReadDir(procDir)
    if err != nil {
        return childPids, err
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }

        // 检查是否为数字目录（进程目录）
        pidStr := entry.Name()
        if pidNum, err := strconv.Atoi(pidStr); err == nil {
            // 读取进程状态文件获取父进程ID
            statusFile := filepath.Join(procDir, pidStr, "status")
            if data, err := ioutil.ReadFile(statusFile); err == nil {
                lines := strings.Split(string(data), "\n")
                for _, line := range lines {
                    if strings.HasPrefix(line, "PPid:") {
                        fields := strings.Fields(line)
                        if len(fields) >= 2 {
                            ppid, err := strconv.Atoi(fields[1])
                            if err == nil && ppid == pid {
                                childPids = append(childPids, pidNum)
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    return childPids, nil
}

// 递归获取进程树的所有PID（包括子进程的子进程）
func getProcessTree(pid int) ([]int, error) {
    allPids := []int{pid}

    // 获取直接子进程
    children, err := getChildProcesses(pid)
    if err != nil {
        return allPids, err
    }

    // 递归获取子进程的子进程
    for _, child := range children {
        grandChildren, err := getProcessTree(child)
        if err == nil {
            allPids = append(allPids, grandChildren...)
        }
    }

    return allPids, nil
}

// 使用进程组杀死整个进程树
func killProcessGroup(pid int) bool {
    if pid <= 0 {
        return false
    }

    logger.Printf("Closing process group, main PID: %d", pid)

    // 方法1：使用进程组（最有效的方法）
    // 负PID表示向进程组发送信号
    if err := syscall.Kill(-pid, syscall.SIGTERM); err == nil {
        logger.Printf("Sent SIGTERM to process group %d", pid)
    } else {
        logger.Printf("Failed to send SIGTERM to process group: %v, trying other methods", err)
    }

    // 等待进程组退出
    for i := 0; i < 5; i++ {
        if !isProcessRunning(pid) {
            logger.Printf("Process group %d has exited", pid)
            return true
        }
        time.Sleep(500 * time.Millisecond)
    }

    // 如果进程组还在，使用进程树方式
    logger.Printf("Process group not fully exited, using process tree method")
    return killProcessTree(pid)
}

// 使用进程树方式杀死进程及其所有子进程
func killProcessTree(pid int) bool {
    if pid <= 0 {
        return false
    }

    logger.Printf("Closing process tree, root PID: %d", pid)

    // 获取进程树的所有PID
    processTree, err := getProcessTree(pid)
    if err != nil {
        logger.Printf("Failed to get process tree: %v, only closing main process", err)
        processTree = []int{pid}
    }

    // 先向所有进程发送SIGTERM（优雅退出）
    for _, p := range processTree {
        if p <= 0 {
            continue
        }

        process, err := os.FindProcess(p)
        if err != nil {
            continue
        }

        // 先尝试优雅关闭
        if err := process.Signal(syscall.SIGTERM); err != nil {
            // 忽略"进程不存在"的错误
            if !strings.Contains(err.Error(), "no such process") &&
               !strings.Contains(err.Error(), "finished") {
                logger.Printf("Failed to send SIGTERM to process %d: %v", p, err)
            }
        }
    }

    // 等待优雅退出
    time.Sleep(2 * time.Second)

    // 检查是否还有进程存活，有则发送SIGKILL
    aliveProcesses := []int{}
    for _, p := range processTree {
        if isProcessRunning(p) {
            aliveProcesses = append(aliveProcesses, p)
        }
    }

    if len(aliveProcesses) > 0 {
        logger.Printf("Still %d processes alive, sending SIGKILL", len(aliveProcesses))

        for _, p := range aliveProcesses {
            process, err := os.FindProcess(p)
            if err != nil {
                continue
            }

            if err := process.Kill(); err != nil {
                logger.Printf("Failed to send SIGKILL to process %d: %v", p, err)
            }
        }

        // 最后检查
        time.Sleep(500 * time.Millisecond)
        finalAlive := []int{}
        for _, p := range aliveProcesses {
            if isProcessRunning(p) {
                finalAlive = append(finalAlive, p)
            }
        }

        if len(finalAlive) > 0 {
            logger.Printf("Warning: Still %d processes cannot be closed", len(finalAlive))
            return false
        }
    }

    logger.Printf("Process tree %d closed successfully", pid)
    return true
}

// ==================== 服务管理 ====================

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

    // 启动停止goroutine
    go func() {
        success := stopService(serviceName)
        doneChan <- success
    }()

    // 等待停止完成或超时
    select {
    case success := <-doneChan:
        if success {
            logger.Printf("[%s] ✓ Shutdown completed normally", serviceName)
        } else {
            logger.Printf("[%s] ⚠ Shutdown completed but may have issues", serviceName)
        }
    case <-timeoutChan:
        logger.Printf("[%s] ⚠ Shutdown timeout after %v, forcing kill...", serviceName, ServiceStopTimeout)
        forceKillService(serviceName)
    }
}

// 停止单个服务
func stopService(serviceName string) bool {
    startTime := time.Now()
    logger.Printf("[%s] Stopping service and all child processes...", serviceName)

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
    logger.Printf("[%s] Current main PID: %d", serviceName, originalPID)

    // 如果服务有停止命令，先尝试使用停止命令
    stopSuccess := false
    if status.Service.StopCmd != "" {
        logger.Printf("[%s] Using stop command: %s", serviceName, status.Service.StopCmd)
        stopSuccess = executeStopCommand(serviceName, status)
    }

    // 无论停止命令是否成功，都使用进程组/进程树方式确保进程被关闭
    if originalPID > 0 {
        logger.Printf("[%s] Closing process tree (PID: %d)", serviceName, originalPID)

        // 根据监控模式选择关闭方式
        var killSuccess bool
        if status.Service.MonitorMode == "monitor" {
            // monitor模式：使用进程组关闭
            killSuccess = killProcessGroup(originalPID)
        } else {
            // self模式：使用进程树关闭
            killSuccess = killProcessTree(originalPID)
        }

        // 验证进程是否已关闭
        if isProcessRunning(originalPID) {
            logger.Printf("[%s] Warning: Main process may still be running (PID: %d)", serviceName, originalPID)
        } else {
            logger.Printf("[%s] Main process closed (PID: %d)", serviceName, originalPID)
            stopSuccess = stopSuccess || killSuccess
        }
    }

    // 清理PID文件
    cleanupPIDFile(status)

    // 对于monitor模式，还需要等待cmd结束
    if status.Service.MonitorMode == "monitor" && status.Cmd != nil && status.Cmd.Process != nil {
        // 等待命令结束，避免僵尸进程
        go func(cmd *exec.Cmd) {
            cmd.Wait()
            logger.Printf("[%s] Command process waited", serviceName)
        }(status.Cmd)
    }

    status.IsRunning = false
    status.PID = 0
    status.Cmd = nil

    shutdownTime := time.Since(startTime)
    if stopSuccess {
        logger.Printf("[%s] ✓ Service and child processes stopped (took: %v)", serviceName, shutdownTime)
        return true
    } else {
        logger.Printf("[%s] ⚠ Service may not be completely stopped (took: %v)", serviceName, shutdownTime)
        return false
    }
}

// 执行停止命令
func executeStopCommand(serviceName string, status *ServiceStatus) bool {
    var cmd *exec.Cmd
    if status.Service.Shell {
        cmd = exec.Command("sh", "-c", status.Service.StopCmd)
    } else {
        parts := strings.Fields(status.Service.StopCmd)
        if len(parts) == 0 {
            logger.Printf("[%s] Empty stop command", serviceName)
            return false
        }
        cmd = exec.Command(parts[0], parts[1:]...)
    }

    cmd.Dir = status.Service.WorkDir

    // 设置超时
    timeout := 5 * time.Second
    done := make(chan error, 1)

    if err := cmd.Start(); err != nil {
        logger.Printf("[%s] Failed to start stop command: %v", serviceName, err)
        return false
    }

    go func() {
        done <- cmd.Wait()
    }()

    select {
    case err := <-done:
        if err != nil {
            logger.Printf("[%s] Stop command execution error: %v", serviceName, err)
            return false
        } else {
            logger.Printf("[%s] Stop command executed successfully", serviceName)
            return true
        }
    case <-time.After(timeout):
        logger.Printf("[%s] Stop command timeout (exceeded %v), terminating command process", serviceName, timeout)
        cmd.Process.Kill()
        cmd.Wait() // 等待进程结束，避免僵尸进程
        return false
    }
}

// 清理PID文件
func cleanupPIDFile(status *ServiceStatus) {
    if status.Service.PIDFile == "" {
        return
    }

    if _, err := os.Stat(status.Service.PIDFile); err == nil {
        if err := os.Remove(status.Service.PIDFile); err != nil {
            logger.Printf("Cannot delete PID file %s: %v", status.Service.PIDFile, err)
        } else {
            logger.Printf("Deleted PID file: %s", status.Service.PIDFile)
        }
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
        // 使用系统kill命令强制杀死进程树
        cmd := exec.Command("pkill", "-9", "-P", strconv.Itoa(status.PID))
        cmd.Run()

        // 再杀死主进程
        cmd = exec.Command("kill", "-9", strconv.Itoa(status.PID))
        cmd.Run()

        // 对于monitor模式，还需要等待cmd结束
        if status.Service.MonitorMode == "monitor" && status.Cmd != nil && status.Cmd.Process != nil {
            // 强制杀死cmd进程
            status.Cmd.Process.Kill()
            // 等待进程结束，避免僵尸进程
            go func(cmd *exec.Cmd) {
                cmd.Wait()
                logger.Printf("[%s] Force killed command process waited", serviceName)
            }(status.Cmd)
        }
    }

    // 强制移除PID文件（仅当PID文件中的PID匹配当前进程时）
    if status.Service.PIDFile != "" {
        if pidData, err := ioutil.ReadFile(status.Service.PIDFile); err == nil {
            filePID, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
            if err == nil && filePID == status.PID {
                os.Remove(status.Service.PIDFile)
            }
        }
    }

    status.IsRunning = false
    status.PID = 0
    status.Cmd = nil
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

// ==================== 进程锁管理 ====================

// 获取进程锁
func acquireProcessLock() error {
    // 获取可执行文件所在目录
    exePath, err := os.Executable()
    if err != nil {
        return fmt.Errorf("failed to get executable path: %v", err)
    }

    exeDir := filepath.Dir(exePath)
    runDir := filepath.Join(exeDir, "..", "var", "run")

    // 创建run目录
    if err := os.MkdirAll(runDir, 0755); err != nil {
        return fmt.Errorf("failed to create run directory: %v", err)
    }

    // 构建锁文件路径
    lockFileName := filepath.Base(exePath) + ".lock"
    lockFilePath = filepath.Join(runDir, lockFileName)

    // 尝试创建并锁定文件
    lockFile, err = os.OpenFile(lockFilePath, os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return fmt.Errorf("failed to create lock file: %v", err)
    }

    // 尝试获取文件锁（非阻塞模式）
    err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
    if err != nil {
        lockFile.Close()

        // 读取已存在的锁文件中的PID
        if pidData, err := ioutil.ReadFile(lockFilePath); err == nil {
            pidStr := strings.TrimSpace(string(pidData))
            if pid, err := strconv.Atoi(pidStr); err == nil {
                // 检查该PID是否还在运行
                if isProcessRunning(pid) {
                    return fmt.Errorf("another instance is already running (PID: %d)", pid)
                } else {
                    // 进程已不存在，清理锁文件并重试
                    os.Remove(lockFilePath)
                    return acquireProcessLock()
                }
            }
        }

        return fmt.Errorf("failed to acquire file lock: %v", err)
    }

    // 将当前PID写入锁文件
    pid := os.Getpid()
    if _, err := lockFile.WriteString(strconv.Itoa(pid)); err != nil {
        releaseProcessLock()
        return fmt.Errorf("failed to write PID to lock file: %v", err)
    }

    // 确保数据写入磁盘
    lockFile.Sync()

    logger.Printf("Process lock acquired (PID: %d, Lock file: %s)", pid, lockFilePath)
    return nil
}

// 释放进程锁
func releaseProcessLock() {
    if lockFile != nil {
        // 释放文件锁
        syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
        lockFile.Close()

        // 删除锁文件
        if lockFilePath != "" {
            os.Remove(lockFilePath)
            logger.Printf("Process lock released (Lock file: %s)", lockFilePath)
        }
    }
}

// ==================== Cgroup管理 ====================

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

// ==================== 配置管理 ====================

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
    setupLoggerWithRotation()
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

// ==================== 服务配置加载 ====================

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

    // 设置默认日志路径，确保在日志目录中
    logDir := filepath.Join(serviceConfig.WorkDir, "log")
    if err := os.MkdirAll(logDir, 0755); err != nil {
        logger.Printf("Failed to create log directory for service %s: %v", serviceConfig.Name, err)
    }

    if serviceConfig.StdoutLog == "" {
        // 使用服务名作为日志文件名
        logFileName := fmt.Sprintf("%s.stdout.log", serviceConfig.Name)
        serviceConfig.StdoutLog = filepath.Join(logDir, logFileName)
    }

    if serviceConfig.StderrLog == "" {
        // 使用服务名作为日志文件名
        logFileName := fmt.Sprintf("%s.stderr.log", serviceConfig.Name)
        serviceConfig.StderrLog = filepath.Join(logDir, logFileName)
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

    // 新增：设置Shell的默认值为true
    // 由于Shell是bool类型，在JSON中不存在的字段会被解析为false
    // 我们需要一个机制来判断这个字段是否在JSON中存在
    // 这里我们使用一个技巧：检查JSON数据中是否包含"shell"字段
    var jsonData map[string]interface{}
    if err := json.Unmarshal(data, &jsonData); err == nil {
        if _, exists := jsonData["shell"]; !exists {
            // JSON中没有shell字段，使用默认值true
            serviceConfig.Shell = true
        }
    } else {
        // 解析失败，使用默认值true
        serviceConfig.Shell = true
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

// ==================== 服务启动 ====================

// 检查并杀死已存在的进程
func checkAndKillExistingProcess(status *ServiceStatus) error {
    if status.Service.PIDFile == "" {
        return nil
    }

    // 检查PID文件是否存在
    if _, err := os.Stat(status.Service.PIDFile); os.IsNotExist(err) {
        return nil // PID文件不存在，无需处理
    }

    // 读取PID文件
    pidData, err := ioutil.ReadFile(status.Service.PIDFile)
    if err != nil {
        return fmt.Errorf("failed to read PID file: %v", err)
    }

    pidStr := strings.TrimSpace(string(pidData))
    if pidStr == "" {
        return fmt.Errorf("PID file is empty")
    }

    pid, err := strconv.Atoi(pidStr)
    if err != nil {
        return fmt.Errorf("invalid PID in PID file: %v", err)
    }

    // 检查该PID对应的进程是否在运行
    if !isProcessRunning(pid) {
        logger.Printf("[PID:%d] Process is not running, cleaning up PID file", pid)
        // 清理无效的PID文件
        os.Remove(status.Service.PIDFile)
        return nil
    }

    logger.Printf("[PID:%d] Process is already running, attempting to kill it", pid)

    // 尝试杀死进程
    if killProcessTree(pid) {
        logger.Printf("[PID:%d] Successfully killed existing process", pid)

        // 等待一段时间确保进程完全退出
        time.Sleep(500 * time.Millisecond)

        // 再次检查进程是否还在运行
        if isProcessRunning(pid) {
            return fmt.Errorf("process %d is still running after kill attempt", pid)
        }

        // 清理PID文件
        os.Remove(status.Service.PIDFile)
        return nil
    } else {
        return fmt.Errorf("failed to kill process %d", pid)
    }
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

    // 检查服务是否已经在运行，避免重复启动
    status.mutex.RLock()
    if status.IsRunning {
        status.mutex.RUnlock()
        return
    }
    status.mutex.RUnlock()

    // 添加一个启动锁，防止并发启动
    var restartMutex sync.Mutex
    restartMutex.Lock()
    defer restartMutex.Unlock()

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

    // 新增：检查PID文件对应的进程是否存在，如果存在则先杀死
    if err := checkAndKillExistingProcess(status); err != nil {
        logger.Printf("[%s] Failed to handle existing process: %v", serviceName, err)
        // 继续尝试启动，不返回错误
    }

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

    // 执行启动命令 - 根据Shell参数决定是否使用shell
    var cmd *exec.Cmd
    if status.Service.Shell {
        cmd = exec.Command("sh", "-c", status.Service.StartCmd)
        logger.Printf("[%s] Using shell to start service", serviceName)
    } else {
        // 不使用shell，直接执行命令和参数
        // 注意：这里需要将命令字符串拆分为命令和参数
        parts := strings.Fields(status.Service.StartCmd)
        if len(parts) == 0 {
            logger.Printf("[%s] Empty start command", serviceName)
            return
        }
        cmd = exec.Command(parts[0], parts[1:]...)
        logger.Printf("[%s] Starting without shell", serviceName)
    }

    cmd.Env = env
    cmd.Dir = status.Service.WorkDir

    // 保存cmd引用，用于后续等待
    status.Cmd = cmd

    // 对于monitor模式，设置进程组以便后续管理
    if status.Service.MonitorMode == "monitor" {
        cmd.SysProcAttr = &syscall.SysProcAttr{
            Setpgid: true, // 设置进程组
            Pgid:    0,    // 创建新的进程组
        }
    }

    // 重定向标准输出和错误输出 - 使用带轮转的日志文件
    stdoutFile, err := openLogFileWithRotation(status.Service.StdoutLog, DefaultRotateConfig)
    if err == nil {
        cmd.Stdout = stdoutFile
        logger.Printf("[%s] Stdout log (with rotation): %s", serviceName, status.Service.StdoutLog)
    } else {
        logger.Printf("[%s] Failed to open stdout log: %v", serviceName, err)
    }

    stderrFile, err := openLogFileWithRotation(status.Service.StderrLog, DefaultRotateConfig)
    if err == nil {
        cmd.Stderr = stderrFile
        logger.Printf("[%s] Stderr log (with rotation): %s", serviceName, status.Service.StderrLog)
    } else {
        logger.Printf("[%s] Failed to open stderr log: %v", serviceName, err)
    }

    logger.Printf("[%s] Working directory: %s", serviceName, status.Service.WorkDir)
    logger.Printf("[%s] Monitor mode: %s", serviceName, status.Service.MonitorMode)
    logger.Printf("[%s] Shell mode: %v", serviceName, status.Service.Shell)

    // 根据监控模式处理PID文件
    if status.Service.MonitorMode == "monitor" {
        logger.Printf("[%s] Running in foreground (monitor mode)", serviceName)
        if err := cmd.Start(); err != nil {
            logger.Printf("[%s] Failed to start service: %v", serviceName, err)

            // 服务启动失败，等待5秒后再尝试重启
            logger.Printf("[%s] Service start failed, will retry in 5 seconds", serviceName)
            time.Sleep(5 * time.Second)

            // 异步重启
            go func() {
                // 添加延迟，避免立即重启
                time.Sleep(100 * time.Millisecond)
                startService(serviceName)
            }()
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
            logger.Printf("[%s] Process group ID: %d", serviceName, pid)
        }

        // 创建一个通道来协调重启
        restartChan := make(chan bool, 1)

        go func() {
            // 等待命令结束，避免僵尸进程
            err := cmd.Wait()

            // 发送重启信号
            select {
            case restartChan <- true:
                // 发送成功
            default:
                // 通道已满，已经有重启信号
            }

            status.mutex.Lock()
            status.IsRunning = false
            status.mutex.Unlock()

            // 检查是否正在关闭，如果不是，可能需要重启
            shutdownMutex.RLock()
            if !isShuttingDown {
                shutdownMutex.RUnlock()
                logger.Printf("[%s] Service exited unexpectedly, will restart in 5 seconds", serviceName)

                // 等待重启信号
                select {
                case <-restartChan:
                    // 等待5秒后重启
                    time.Sleep(5 * time.Second)

                    // 再次检查是否正在关闭
                    shutdownMutex.RLock()
                    if !isShuttingDown {
                        shutdownMutex.RUnlock()
                        // 异步重启，避免阻塞
                        go func() {
                            time.Sleep(100 * time.Millisecond)
                            startService(serviceName)
                        }()
                    } else {
                        shutdownMutex.RUnlock()
                    }
                case <-time.After(6 * time.Second):
                    // 超时，不重启
                }
            } else {
                shutdownMutex.RUnlock()
                if err != nil {
                    logger.Printf("[%s] Service exited during shutdown with error: %v", serviceName, err)
                } else {
                    logger.Printf("[%s] Service exited during shutdown", serviceName)
                }
            }
        }()

        // 启动一个goroutine来检查服务是否快速退出
        go func() {
            time.Sleep(1 * time.Second)
            select {
            case <-restartChan:
                // 服务已经退出，重启逻辑由上面的goroutine处理
            default:
                // 服务还在运行
            }
        }()
    } else {
        logger.Printf("[%s] Running in background (self mode)", serviceName)
        if err := cmd.Start(); err != nil {
            logger.Printf("[%s] Failed to start service: %v", serviceName, err)
            return
        }

        // 对于self模式，启动一个goroutine来等待sh进程，避免僵尸进程
        go func() {
            err := cmd.Wait()
            if err != nil {
                logger.Printf("[%s] Shell process exited with error: %v", serviceName, err)
            } else {
                logger.Printf("[%s] Shell process exited successfully", serviceName)
            }
        }()

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
    status.FailCount = 0
    logger.Printf("[%s] ✓ Service started successfully", serviceName)
}

// ==================== 服务监控 ====================

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

func restartService(serviceName string) {
    logger.Printf("[%s] === Restarting Service ===", serviceName)

    // 快速停止服务，不等待太长时间
    stopSuccess := stopService(serviceName)

    if stopSuccess {
        // 等待1秒
        logger.Printf("[%s] Service stopped successfully, waiting 1 second before restart", serviceName)
        time.Sleep(1 * time.Second)
    } else {
        // 如果停止失败，等待更短时间
        logger.Printf("[%s] Stop failed or incomplete, waiting 500ms before restart", serviceName)
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

    // 添加额外的重启延迟，确保至少等待5秒
    logger.Printf("[%s] Waiting additional 4 seconds before restart...", serviceName)
    time.Sleep(4 * time.Second)

    // 重新启动服务
    go startService(serviceName)

    logger.Printf("[%s] === Restart Initiated ===", serviceName)
}

// ==================== 定时任务 ====================

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

    // 每小时检查一次日志轮转
    cronScheduler.AddFunc("@hourly", func() {
        rotateAllServiceLogs()
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

    // 添加日志文件信息
    logger.Println("========== Log File Status ==========")

    // 检查监控器日志
    if monitorConfig.LogPath != "" {
        logFile := filepath.Join(monitorConfig.LogPath, "monitor.log")
        if info, err := os.Stat(logFile); err == nil {
            sizeMB := float64(info.Size()) / (1024 * 1024)
            logger.Printf("Monitor log: %.2f MB", sizeMB)
        }
    }

    for name, status := range services {
        status.mutex.RLock()

        // 检查stdout日志
        if status.Service.StdoutLog != "" {
            if info, err := os.Stat(status.Service.StdoutLog); err == nil {
                sizeMB := float64(info.Size()) / (1024 * 1024)
                if sizeMB > 4.5 { // 接近5MB时警告
                    logger.Printf("[%s] Stdout log: %.2f MB (接近限制)", name, sizeMB)
                } else {
                    logger.Printf("[%s] Stdout log: %.2f MB", name, sizeMB)
                }
            }
        }

        // 检查stderr日志
        if status.Service.StderrLog != "" {
            if info, err := os.Stat(status.Service.StderrLog); err == nil {
                sizeMB := float64(info.Size()) / (1024 * 1024)
                if sizeMB > 4.5 { // 接近5MB时警告
                    logger.Printf("[%s] Stderr log: %.2f MB (接近限制)", name, sizeMB)
                } else {
                    logger.Printf("[%s] Stderr log: %.2f MB", name, sizeMB)
                }
            }
        }

        status.mutex.RUnlock()
    }

    logger.Println("==================================")
}

// ==================== 主循环 ====================

func waitForShutdown() {
    logger.Println("Agent is now running. Press Ctrl+C or send SIGTERM for graceful shutdown.")

    // 阻塞主线程，等待信号
    select {}
}