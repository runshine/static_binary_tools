package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ==================== API 响应结构体 ====================

// APIResponse 通用 API 响应结构
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ServiceBrief 服务简要信息
type ServiceBrief struct {
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	IsRunning     bool      `json:"is_running"`
	PID           int       `json:"pid"`
	StartTime     time.Time `json:"start_time"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	FailCount     int       `json:"fail_count"`
	LastCheck     time.Time `json:"last_check"`
	MonitorMode   string    `json:"monitor_mode"`
}

// ServiceDetail 服务详细信息
type ServiceDetail struct {
	ServiceBrief
	Config struct {
		WorkDir       string   `json:"work_dir"`
		StdoutLog     string   `json:"stdout_log"`
		StderrLog     string   `json:"stderr_log"`
		CheckInterval int      `json:"check_interval"`
		MaxFailures   int      `json:"max_failures"`
		DependsOn     []string `json:"depends_on"`
		StartCmd      string   `json:"start_cmd"`
		StopCmd       string   `json:"stop_cmd"`
		RestartCmd    string   `json:"restart_cmd"`
	} `json:"config"`
}

// AgentInfo Agent 综合状态信息
type AgentInfo struct {
	// 版本信息
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`

	// 基本信息
	UUID      string `json:"uuid"`
	ProjectID string `json:"project_id"`
	Workspace string `json:"workspace"`
	Server    string `json:"server"`

	// 运行状态
	UptimeSeconds int64  `json:"uptime_seconds"`
	StartTime     string `json:"start_time"`
	Status        string `json:"status"` // running, shutting_down

	// 服务统计
	ServicesTotal   int `json:"services_total"`
	ServicesRunning int `json:"services_running"`
	ServicesStopped int `json:"services_stopped"`
	ServicesError   int `json:"services_error"` // 有失败计数的服务数量

	// 服务简要状态列表
	Services []ServiceStatusBrief `json:"services"`
}

// ServiceStatusBrief 服务简要状态
type ServiceStatusBrief struct {
	Name        string `json:"name"`
	IsRunning   bool   `json:"is_running"`
	PID         int    `json:"pid"`
	Uptime      int64  `json:"uptime_seconds"`
	FailCount   int    `json:"fail_count"`
	MonitorMode string `json:"monitor_mode"`
}

// LogResponse 日志响应
type LogResponse struct {
	ServiceName string   `json:"service_name"`
	LogType     string   `json:"log_type"`
	Lines       []string `json:"lines"`
	TotalLines  int      `json:"total_lines"`
	LogFile     string   `json:"log_file"`
}

// API 错误码
const (
	APICodeSuccess         = 0
	APICodeServiceNotFound = 1001
	APICodeServiceRunning  = 1002
	APICodeServiceStopped  = 1003
	APICodeShuttingDown    = 1004
	APICodeUninstallFailed = 1005
	APICodeBadRequest      = 2001
	APICodeUnauthorized    = 2002
	APICodeInternalError   = 5001
)

// API 服务器
var apiServer *http.Server
var agentStartTime time.Time

// ==================== API 服务器启动 ====================

// startAPIServer 启动 HTTP API 服务器
func startAPIServer() {
	agentStartTime = time.Now()

	if !monitorConfig.APIEnabled {
		logger.Println("API server disabled")
		return
	}

	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/api/v1/agent/health", handleHealth)
	mux.HandleFunc("/api/v1/agent/info", authMiddleware(handleAgentInfo))
	mux.HandleFunc("/api/v1/agent/uninstall", authMiddleware(handleAgentUninstall))
	mux.HandleFunc("/api/v1/services", authMiddleware(handleServices))
	mux.HandleFunc("/api/v1/services/", authMiddleware(handleServiceRouter))

	// 配置服务器
	apiServer = &http.Server{
		Addr:         monitorConfig.APIListen,
		Handler:      corsMiddleware(loggingMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		logger.Printf("API server starting on %s", monitorConfig.APIListen)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("API server error: %v", err)
		}
	}()
}

// ==================== 中间件 ====================

// authMiddleware Token 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 如果未配置 token，跳过认证
		if monitorConfig.APIAuthToken == "" {
			next(w, r)
			return
		}

		// 从 Header 获取 token
		token := r.Header.Get("X-API-Token")
		if token == "" {
			// 从 URL 参数获取
			token = r.URL.Query().Get("token")
		}

		if token != monitorConfig.APIAuthToken {
			respondError(w, APICodeUnauthorized, "Unauthorized")
			return
		}

		next(w, r)
	}
}

// loggingMiddleware 请求日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Printf("[API] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		logger.Printf("[API] %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// corsMiddleware CORS 中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==================== 辅助函数 ====================

// respondJSON 返回 JSON 响应
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondSuccess 返回成功响应
func respondSuccess(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusOK, APIResponse{
		Code:    APICodeSuccess,
		Message: "success",
		Data:    data,
	})
}

// respondError 返回错误响应
func respondError(w http.ResponseWriter, code int, message string) {
	respondJSON(w, http.StatusOK, APIResponse{
		Code:    code,
		Message: message,
	})
}

// ==================== 处理器 ====================

// handleHealth 健康检查
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, APICodeBadRequest, "Method not allowed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleAgentInfo 获取 Agent 综合状态信息
func handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, APICodeBadRequest, "Method not allowed")
		return
	}

	// 检查是否正在关闭
	shutdownMutex.RLock()
	isShuttingDown := isShuttingDown
	shutdownMutex.RUnlock()

	status := "running"
	if isShuttingDown {
		status = "shutting_down"
	}

	// 收集服务统计信息
	serviceMutex.RLock()
	defer serviceMutex.RUnlock()

	totalServices := len(services)
	runningCount := 0
	stoppedCount := 0
	errorCount := 0
	serviceList := make([]ServiceStatusBrief, 0, totalServices)

	for name, svc := range services {
		svc.mutex.RLock()
		var uptime int64
		if !svc.StartTime.IsZero() {
			uptime = int64(time.Since(svc.StartTime).Seconds())
		}

		if svc.IsRunning {
			runningCount++
		} else {
			stoppedCount++
		}
		if svc.FailCount > 0 {
			errorCount++
		}

		serviceList = append(serviceList, ServiceStatusBrief{
			Name:        name,
			IsRunning:   svc.IsRunning,
			PID:         svc.PID,
			Uptime:      uptime,
			FailCount:   svc.FailCount,
			MonitorMode: svc.Service.MonitorMode,
		})
		svc.mutex.RUnlock()
	}

	respondSuccess(w, AgentInfo{
		// 版本信息
		Version:   BuildVersion,
		GoVersion: "go1.21",
		Platform:  "linux/amd64",

		// 基本信息
		UUID:      monitorConfig.UUID,
		ProjectID: monitorConfig.ProjectID,
		Workspace: monitorConfig.Workspace,
		Server:    fmt.Sprintf("%s:%s", monitorConfig.ServerAddr, monitorConfig.ServerPort),

		// 运行状态
		UptimeSeconds: int64(time.Since(agentStartTime).Seconds()),
		StartTime:     agentStartTime.Format(time.RFC3339),
		Status:        status,

		// 服务统计
		ServicesTotal:   totalServices,
		ServicesRunning: runningCount,
		ServicesStopped: stoppedCount,
		ServicesError:   errorCount,

		// 服务简要状态列表
		Services: serviceList,
	})
}

// handleServices 获取服务列表
func handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, APICodeBadRequest, "Method not allowed")
		return
	}

	serviceMutex.RLock()
	defer serviceMutex.RUnlock()

	serviceList := make([]ServiceBrief, 0, len(services))
	runningCount := 0

	for name, status := range services {
		status.mutex.RLock()
		var uptime int64
		if !status.StartTime.IsZero() {
			uptime = int64(time.Since(status.StartTime).Seconds())
		}
		if status.IsRunning {
			runningCount++
		}

		serviceList = append(serviceList, ServiceBrief{
			Name:          name,
			Description:   status.Service.Description,
			IsRunning:     status.IsRunning,
			PID:           status.PID,
			StartTime:     status.StartTime,
			UptimeSeconds: uptime,
			FailCount:     status.FailCount,
			LastCheck:     status.LastCheck,
			MonitorMode:   status.Service.MonitorMode,
		})
		status.mutex.RUnlock()
	}

	respondSuccess(w, map[string]interface{}{
		"services":      serviceList,
		"total":         len(services),
		"running_count": runningCount,
	})
}

// handleServiceRouter 服务路由分发
func handleServiceRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/services/")
	if path == "" {
		respondError(w, APICodeBadRequest, "Service name required")
		return
	}

	parts := strings.Split(path, "/")
	serviceName := parts[0]

	// 检查服务是否存在
	serviceMutex.RLock()
	status, exists := services[serviceName]
	serviceMutex.RUnlock()

	if !exists {
		respondError(w, APICodeServiceNotFound, fmt.Sprintf("Service not found: %s", serviceName))
		return
	}

	// 根据路径分发
	if len(parts) == 1 {
		// GET /api/v1/services/{name}
		if r.Method == http.MethodGet {
			handleServiceDetail(w, r, serviceName, status)
			return
		}
		respondError(w, APICodeBadRequest, "Method not allowed")
		return
	}

	action := parts[1]
	switch action {
	case "start":
		if r.Method != http.MethodPost {
			respondError(w, APICodeBadRequest, "Method not allowed")
			return
		}
		handleServiceStart(w, r, serviceName)
	case "stop":
		if r.Method != http.MethodPost {
			respondError(w, APICodeBadRequest, "Method not allowed")
			return
		}
		handleServiceStop(w, r, serviceName)
	case "restart":
		if r.Method != http.MethodPost {
			respondError(w, APICodeBadRequest, "Method not allowed")
			return
		}
		handleServiceRestart(w, r, serviceName)
	case "logs":
		if r.Method != http.MethodGet {
			respondError(w, APICodeBadRequest, "Method not allowed")
			return
		}
		handleServiceLogs(w, r, serviceName, status)
	default:
		respondError(w, APICodeBadRequest, fmt.Sprintf("Unknown action: %s", action))
	}
}

// handleServiceDetail 获取服务详情
func handleServiceDetail(w http.ResponseWriter, r *http.Request, serviceName string, status *ServiceStatus) {
	status.mutex.RLock()
	defer status.mutex.RUnlock()

	var uptime int64
	if !status.StartTime.IsZero() {
		uptime = int64(time.Since(status.StartTime).Seconds())
	}

	detail := ServiceDetail{
		ServiceBrief: ServiceBrief{
			Name:          serviceName,
			Description:   status.Service.Description,
			IsRunning:     status.IsRunning,
			PID:           status.PID,
			StartTime:     status.StartTime,
			UptimeSeconds: uptime,
			FailCount:     status.FailCount,
			LastCheck:     status.LastCheck,
			MonitorMode:   status.Service.MonitorMode,
		},
	}
	detail.Config.WorkDir = status.Service.WorkDir
	detail.Config.StdoutLog = status.Service.StdoutLog
	detail.Config.StderrLog = status.Service.StderrLog
	detail.Config.CheckInterval = status.Service.CheckInterval
	detail.Config.MaxFailures = status.Service.MaxFailures
	detail.Config.DependsOn = status.Service.DependsOn
	detail.Config.StartCmd = status.Service.StartCmd
	detail.Config.StopCmd = status.Service.StopCmd
	detail.Config.RestartCmd = status.Service.RestartCmd

	respondSuccess(w, detail)
}

// handleServiceStart 启动服务
func handleServiceStart(w http.ResponseWriter, r *http.Request, serviceName string) {
	serviceMutex.RLock()
	status := services[serviceName]
	serviceMutex.RUnlock()

	status.mutex.RLock()
	isRunning := status.IsRunning
	status.mutex.RUnlock()

	if isRunning {
		respondError(w, APICodeServiceRunning, "Service already running")
		return
	}

	shutdownMutex.RLock()
	shuttingDown := isShuttingDown
	shutdownMutex.RUnlock()

	if shuttingDown {
		respondError(w, APICodeShuttingDown, "System is shutting down")
		return
	}

	// 异步启动服务
	go startService(serviceName)

	respondSuccess(w, map[string]interface{}{
		"name":   serviceName,
		"action": "start",
		"status": "initiated",
	})
}

// handleServiceStop 停止服务
func handleServiceStop(w http.ResponseWriter, r *http.Request, serviceName string) {
	serviceMutex.RLock()
	status := services[serviceName]
	serviceMutex.RUnlock()

	status.mutex.RLock()
	isRunning := status.IsRunning
	status.mutex.RUnlock()

	if !isRunning {
		respondError(w, APICodeServiceStopped, "Service not running")
		return
	}

	// 异步停止服务
	go stopService(serviceName)

	respondSuccess(w, map[string]interface{}{
		"name":   serviceName,
		"action": "stop",
		"status": "initiated",
	})
}

// handleServiceRestart 重启服务
func handleServiceRestart(w http.ResponseWriter, r *http.Request, serviceName string) {
	shutdownMutex.RLock()
	shuttingDown := isShuttingDown
	shutdownMutex.RUnlock()

	if shuttingDown {
		respondError(w, APICodeShuttingDown, "System is shutting down")
		return
	}

	// 异步重启服务
	go restartService(serviceName)

	respondSuccess(w, map[string]interface{}{
		"name":   serviceName,
		"action": "restart",
		"status": "initiated",
	})
}

// handleServiceLogs 获取服务日志
func handleServiceLogs(w http.ResponseWriter, r *http.Request, serviceName string, status *ServiceStatus) {
	// 解析参数
	linesStr := r.URL.Query().Get("lines")
	lines := 100 // 默认 100 行
	if linesStr != "" {
		if n, err := strconv.Atoi(linesStr); err == nil && n > 0 {
			lines = n
		}
	}

	logType := r.URL.Query().Get("type")
	if logType == "" {
		logType = "stdout"
	}

	// 获取日志文件路径
	status.mutex.RLock()
	var logFile string
	switch logType {
	case "stdout":
		logFile = status.Service.StdoutLog
	case "stderr":
		logFile = status.Service.StderrLog
	default:
		status.mutex.RUnlock()
		respondError(w, APICodeBadRequest, "Invalid log type, must be 'stdout' or 'stderr'")
		return
	}
	status.mutex.RUnlock()

	if logFile == "" {
		respondError(w, APICodeBadRequest, fmt.Sprintf("No %s log file configured", logType))
		return
	}

	// 读取日志文件
	logLines, totalLines, err := readLastLines(logFile, lines)
	if err != nil {
		respondError(w, APICodeInternalError, fmt.Sprintf("Failed to read log file: %v", err))
		return
	}

	respondSuccess(w, LogResponse{
		ServiceName: serviceName,
		LogType:     logType,
		Lines:       logLines,
		TotalLines:  totalLines,
		LogFile:     logFile,
	})
}

// handleAgentUninstall 卸载 Agent（停止服务、删除工作空间、退出自身）
func handleAgentUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, APICodeBadRequest, "Method not allowed")
		return
	}

	workspacePath := strings.TrimSpace(monitorConfig.Workspace)
	if err := validateWorkspaceForUninstall(workspacePath); err != nil {
		respondError(w, APICodeUninstallFailed, fmt.Sprintf("Uninstall validation failed: %v", err))
		return
	}

	respondSuccess(w, map[string]interface{}{
		"action":    "uninstall",
		"status":    "initiated",
		"workspace": workspacePath,
	})

	// 返回响应后异步执行卸载，避免请求中断导致前端无法拿到结果
	go func(ws string) {
		time.Sleep(300 * time.Millisecond)
		if err := performUninstall(ws); err != nil {
			logger.Printf("Uninstall failed: %v", err)
		}
	}(workspacePath)
}

// readLastLines 读取文件最后 N 行
func readLastLines(filename string, n int) ([]string, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, 0, nil
		}
		return nil, 0, err
	}
	defer file.Close()

	// 统计总行数并读取最后 n 行
	scanner := bufio.NewScanner(file)
	var allLines []string
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, 0, err
	}

	total := len(allLines)
	if total == 0 {
		return []string{}, 0, nil
	}

	start := total - n
	if start < 0 {
		start = 0
	}

	return allLines[start:], total, nil
}
