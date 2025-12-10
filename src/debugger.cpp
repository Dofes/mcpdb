#include "debugger.h"

#include <fmt/format.h>

#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define closesocket close
#endif

// ============== PathUtils 实现 ==============

namespace PathUtils {

// 路径映射表：模块路径 -> 文件系统路径
// 例如: "ark_scripts.system.entity_rank.entityrankserver" ->
// "c:/gitrepo/arkcraft-core/beh/ark_scripts/system/entity_rank/entityRankServer.py"
static std::unordered_map<std::string, std::string> g_pathMapping;
static std::mutex                                   g_pathMappingMutex;

std::string normalize(const std::string& path) {
    std::string result = path;
    for (char& c : result) {
        if (c == '\\') c = '/';
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return result;
}

// 将 Python 模块路径转换为文件路径格式（用于匹配）
// 例如: ark_scripts.system.entity_rank.entityRankServer -> ark_scripts/system/entity_rank/entityrankserver.py
std::string moduleToPath(const std::string& moduleName) {
    std::string result = moduleName;
    for (char& c : result) {
        if (c == '.') c = '/';
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    result += ".py";
    return result;
}

// 检查字符串是否看起来像 Python 模块路径（包含点但不包含斜杠，且不以 .py 结尾）
bool looksLikeModulePath(const std::string& path) {
    if (path.find('/') != std::string::npos || path.find('\\') != std::string::npos) {
        return false;
    }
    if (path.find('.') == std::string::npos) {
        return false;
    }
    // 检查是否以 .py 结尾
    if (path.length() >= 3 && path.substr(path.length() - 3) == ".py") {
        return false;
    }
    return true;
}

// 注册路径映射：当设置断点时，记录文件路径与可能的模块路径的对应关系
void registerPathMapping(const std::string& filePath) {
    std::string normalized = normalize(filePath);
    // 从文件路径提取可能的模块路径键
    // 例如: c:/gitrepo/arkcraft-core/beh/ark_scripts/system/entity_rank/entityRankServer.py
    // 提取: ark_scripts/system/entity_rank/entityrankserver.py (小写，用于匹配)

    std::lock_guard<std::mutex> lock(g_pathMappingMutex);
    g_pathMapping[normalized] = filePath; // 保存原始路径（保留大小写）
}

// 将模块路径转换为文件系统路径（用于发送给 VSCode）
std::string resolveToFilePath(const std::string& sourcePath) {
    // 如果已经是文件路径格式，直接返回
    if (!looksLikeModulePath(sourcePath)) {
        return sourcePath;
    }

    // 将模块路径转换为路径后缀用于匹配
    std::string moduleSuffix = moduleToPath(sourcePath);

    std::lock_guard<std::mutex> lock(g_pathMappingMutex);

    // 在已注册的路径中查找匹配的
    for (const auto& [normalizedPath, originalPath] : g_pathMapping) {
        if (normalizedPath.length() >= moduleSuffix.length()) {
            std::string suffix = normalizedPath.substr(normalizedPath.length() - moduleSuffix.length());
            if (suffix == moduleSuffix) {
                // 检查前一个字符是否是路径分隔符
                if (normalizedPath.length() == moduleSuffix.length()) {
                    return originalPath;
                }
                char prev = normalizedPath[normalizedPath.length() - moduleSuffix.length() - 1];
                if (prev == '/' || prev == '\\') {
                    return originalPath;
                }
            }
        }
    }

    // 没找到映射，返回原始路径
    return sourcePath;
}

// 清除路径映射
void clearPathMapping() {
    std::lock_guard<std::mutex> lock(g_pathMappingMutex);
    g_pathMapping.clear();
}

bool matches(const std::string& breakpointPath, const std::string& sourcePath) {
    std::string bp  = normalize(breakpointPath);
    std::string src = normalize(sourcePath);

    if (bp == src) return true;

    // 尾部匹配
    auto checkSuffix = [](const std::string& longer, const std::string& shorter) {
        if (longer.length() > shorter.length()) {
            if (longer.substr(longer.length() - shorter.length()) == shorter) {
                char prev = longer[longer.length() - shorter.length() - 1];
                return (prev == '/' || prev == '\\');
            }
        }
        return false;
    };

    if (checkSuffix(bp, src) || checkSuffix(src, bp)) {
        return true;
    }

    // 支持 Python 模块路径格式匹配
    // 例如: ark_scripts.system.entity_rank.entityRankServer 匹配
    //       c:/gitrepo/arkcraft-core/beh/ark_scripts/system/entity_rank/entityrankserver.py
    std::string bpModule, srcModule;

    if (looksLikeModulePath(breakpointPath)) {
        bpModule = moduleToPath(breakpointPath);
        if (src.length() >= bpModule.length()) {
            std::string srcSuffix = src.substr(src.length() - bpModule.length());
            if (srcSuffix == bpModule) {
                if (src.length() == bpModule.length()) return true;
                char prev = src[src.length() - bpModule.length() - 1];
                if (prev == '/' || prev == '\\') return true;
            }
        }
    }

    if (looksLikeModulePath(sourcePath)) {
        srcModule = moduleToPath(sourcePath);
        if (bp.length() >= srcModule.length()) {
            std::string bpSuffix = bp.substr(bp.length() - srcModule.length());
            if (bpSuffix == srcModule) {
                if (bp.length() == srcModule.length()) return true;
                char prev = bp[bp.length() - srcModule.length() - 1];
                if (prev == '/' || prev == '\\') return true;
            }
        }
    }

    return false;
}

} // namespace PathUtils

// ============== DAPMessageBuilder 实现 ==============

std::atomic<int> g_messageSeq{1};

json DAPMessageBuilder::response(int requestSeq, const std::string& command, bool success, const json& body) {
    json resp = {
        {        "seq",  nextSeq()},
        {       "type", "response"},
        {"request_seq", requestSeq},
        {    "success",    success},
        {    "command",    command}
    };
    if (!body.is_null()) {
        resp["body"] = body;
    }
    return resp;
}

json DAPMessageBuilder::event(const std::string& eventName, const json& body) {
    json evt = {
        {  "seq", nextSeq()},
        { "type",   "event"},
        {"event", eventName}
    };
    if (!body.is_null()) {
        evt["body"] = body;
    }
    return evt;
}

int DAPMessageBuilder::nextSeq() { return g_messageSeq++; }

// ============== DAPDebugger 实现 ==============

DAPDebugger& DAPDebugger::getInstance() {
    static DAPDebugger instance;
    return instance;
}

DAPDebugger::DAPDebugger() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

DAPDebugger::~DAPDebugger() {
    shutdown();
#ifdef _WIN32
    WSACleanup();
#endif
}

bool DAPDebugger::initialize(int port) {
    state_ = DebuggerState::Initializing;
    startServer(port);

    std::cout << "[DAP] Waiting for debugger to attach..." << std::endl;
    waitForCommand();
    std::cout << "[DAP] Debugger attached, starting execution" << std::endl;

    return true;
}

void DAPDebugger::shutdown() {
    stopServer();
    state_ = DebuggerState::Disconnected;
}

// ============== 网络通信 ==============

void DAPDebugger::startServer(int port) {
    if (serverRunning_) return;

    serverRunning_ = true;
    serverStarted_ = false;

    // 先获取锁，确保主线程在子线程通知前进入等待状态
    std::unique_lock<std::mutex> startLock(serverStartMutex_);

    serverThread_ = std::thread([this, port]() {
        auto notifyStarted = [this](bool success) {
            {
                std::lock_guard<std::mutex> lock(serverStartMutex_);
                serverStarted_ = success;
            }
            serverStartCV_.notify_all();
        };

        serverSocket_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (serverSocket_ < 0) {
            std::cerr << "[DAP] Failed to create socket" << std::endl;
            std::cerr.flush();
            notifyStarted(false);
            return;
        }

        int opt = 1;
        setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(static_cast<u_short>(port));

        if (bind(serverSocket_, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[DAP] Failed to bind to port " << port << std::endl;
            std::cerr.flush();
            closesocket(serverSocket_);
            notifyStarted(false);
            return;
        }

        listen(serverSocket_, 1);
        std::cout << "[DAP] Debug adapter listening on port " << port << std::endl;
        std::cout.flush();
        notifyStarted(true);

        while (serverRunning_) {
            sockaddr_in clientAddr{};
            socklen_t   clientLen = sizeof(clientAddr);
            clientSocket_         = static_cast<int>(accept(serverSocket_, (sockaddr*)&clientAddr, &clientLen));

            if (clientSocket_ < 0) continue;

            std::cout << "[DAP] Client connected" << std::endl;
            std::cout.flush();
            state_ = DebuggerState::Initializing;

            char        buffer[65536];
            std::string messageBuffer;

            while (serverRunning_ && clientSocket_ >= 0) {
                int received = recv(clientSocket_, buffer, sizeof(buffer) - 1, 0);
                if (received <= 0) break;

                buffer[received]  = '\0';
                messageBuffer    += buffer;

                // 解析 DAP 消息
                while (true) {
                    size_t headerEnd = messageBuffer.find("\r\n\r\n");
                    if (headerEnd == std::string::npos) break;

                    size_t clPos = messageBuffer.find("Content-Length:");
                    if (clPos == std::string::npos) {
                        messageBuffer = messageBuffer.substr(headerEnd + 4);
                        continue;
                    }

                    int    contentLength = 0;
                    size_t numStart      = clPos + 15;
                    while (numStart < headerEnd && messageBuffer[numStart] == ' ') numStart++;
                    while (numStart < headerEnd && messageBuffer[numStart] >= '0' && messageBuffer[numStart] <= '9') {
                        contentLength = contentLength * 10 + (messageBuffer[numStart] - '0');
                        numStart++;
                    }

                    size_t bodyStart = headerEnd + 4;
                    if (messageBuffer.size() < bodyStart + contentLength) break;

                    std::string body = messageBuffer.substr(bodyStart, contentLength);
                    messageBuffer    = messageBuffer.substr(bodyStart + contentLength);

                    handleRequest(body);
                }
            }

            std::cout << "[DAP] Client disconnected" << std::endl;
            std::cout.flush();
            closesocket(clientSocket_);
            clientSocket_ = -1;
        }
    });

    // 等待服务器启动完成（锁已经在创建线程前获取）
    serverStartCV_.wait(startLock, [this] { return serverStarted_.load() || !serverRunning_.load(); });
}

void DAPDebugger::stopServer() {
    serverRunning_ = false;
    if (clientSocket_ >= 0) {
        closesocket(clientSocket_);
        clientSocket_ = -1;
    }
    if (serverSocket_ >= 0) {
        closesocket(serverSocket_);
        serverSocket_ = -1;
    }
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
}

void DAPDebugger::sendMessage(const json& message) { sendRaw(message.dump()); }

void DAPDebugger::sendRaw(const std::string& message) const {
    if (clientSocket_ < 0) return;

    std::string packet = fmt::format("Content-Length: {}\r\n\r\n{}", message.size(), message);
    send(clientSocket_, packet.c_str(), static_cast<int>(packet.size()), 0);
}

// ============== DAP 协议处理 ==============

void DAPDebugger::handleRequest(const std::string& request) {
    std::cout << "[DAP] Received: " << request.substr(0, 200) << (request.size() > 200 ? "..." : "") << std::endl;

    try {
        json req = json::parse(request);

        std::string command = req.value("command", "");
        int         seq     = req.value("seq", 0);
        json        args    = req.value("arguments", json::object());

        // 命令分发
        if (command == "initialize") {
            processInitialize(seq, args);
        } else if (command == "launch") {
            processLaunch(seq, args);
        } else if (command == "attach") {
            std::cout << "[DAP] Attaching debugger" << args.dump() << std::endl;
            processAttach(seq, args);
        } else if (command == "setBreakpoints") {
            std::cout << "[DAP] Setting breakpoints" << args.dump() << std::endl;
            processSetBreakpoints(seq, args);
        } else if (command == "configurationDone") {
            processConfigurationDone(seq, args);
        } else if (command == "threads") {
            processThreads(seq, args);
        } else if (command == "stackTrace") {
            processStackTrace(seq, args);
        } else if (command == "scopes") {
            processScopes(seq, args);
        } else if (command == "variables") {
            processVariables(seq, args);
        } else if (command == "continue") {
            processContinue(seq, args);
        } else if (command == "next") {
            processNext(seq, args);
        } else if (command == "stepIn") {
            processStepIn(seq, args);
        } else if (command == "stepOut") {
            processStepOut(seq, args);
        } else if (command == "pause") {
            processPause(seq, args);
        } else if (command == "evaluate") {
            processEvaluate(seq, args);
        } else if (command == "disconnect") {
            processDisconnect(seq, args);
        } else {
            sendMessage(
                DAPMessageBuilder::response(
                    seq,
                    command,
                    false,
                    {
                        {"message", "Unknown command: " + command}
            }
                )
            );
        }
    } catch (const json::exception& e) {
        std::cerr << "[DAP] JSON parse error: " << e.what() << std::endl;
    }
}

void DAPDebugger::processInitialize(int seq, const json& /*args*/) {
    json capabilities = {
        { "supportsConfigurationDoneRequest",  true},
        {      "supportsFunctionBreakpoints", false},
        {   "supportsConditionalBreakpoints",  true},
        {"supportsHitConditionalBreakpoints", false},
        {        "supportsEvaluateForHovers",  true},
        {                 "supportsStepBack", false},
        {              "supportsSetVariable", false},
        {             "supportsRestartFrame", false},
        {       "supportsGotoTargetsRequest", false},
        {     "supportsStepInTargetsRequest", false},
        {       "supportsCompletionsRequest", false},
        {           "supportsModulesRequest", false},
        {         "supportsExceptionOptions", false},
        {   "supportsValueFormattingOptions", false},
        {     "supportsExceptionInfoRequest", false},
        {         "supportTerminateDebuggee",  true},
        { "supportsDelayedStackTraceLoading", false},
        {     "supportsLoadedSourcesRequest", false}
    };

    sendMessage(DAPMessageBuilder::response(seq, "initialize", true, capabilities));
    sendMessage(DAPMessageBuilder::event("initialized"));
}

void DAPDebugger::processLaunch(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "launch", true));
    state_ = DebuggerState::Running;
}

void DAPDebugger::processAttach(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "attach", true));
    state_ = DebuggerState::Running;
}

void DAPDebugger::processSetBreakpoints(int seq, const json& args) {
    std::string sourcePath;
    if (args.contains("source") && args["source"].contains("path")) {
        sourcePath = args["source"]["path"].get<std::string>();
    }

    clearBreakpoints(sourcePath);

    json verifiedBreakpoints = json::array();

    if (args.contains("breakpoints")) {
        for (const auto& bp : args["breakpoints"]) {
            int line = bp.value("line", 0);
            if (line > 0) {
                int bpId = setBreakpoint(sourcePath, line);
                verifiedBreakpoints.push_back({
                    {      "id", bpId},
                    {"verified", true},
                    {    "line", line}
                });
            }
        }
    }

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "setBreakpoints",
            true,
            {
                {"breakpoints", verifiedBreakpoints}
    }
        )
    );
}

void DAPDebugger::processConfigurationDone(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "configurationDone", true));
    state_ = DebuggerState::Running;
    notifyCommandReceived();
}

void DAPDebugger::processThreads(int seq, const json& /*args*/) {
    json threads = json::array();
    threads.push_back({
        {  "id",            1},
        {"name", "MainThread"}
    });
    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "threads",
            true,
            {
                {"threads", threads}
    }
        )
    );
}

void DAPDebugger::processStackTrace(int seq, const json& /*args*/) {
    std::lock_guard<std::mutex> lock(frameMutex_);

    json frames = json::array();
    for (const auto& frame : stackFrames_) {
        frames.push_back(frame.toJson());
    }

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "stackTrace",
            true,
            {
                {"stackFrames",              frames},
                {"totalFrames", stackFrames_.size()}
    }
        )
    );
}

void DAPDebugger::processScopes(int seq, const json& args) {
    int frameId = args.value("frameId", 0);

    json scopes = json::array();
    scopes.push_back({
        {              "name",                                                  "Locals"},
        {"variablesReference", frameId * dap::kScopeMultiplier + dap::kLocalsScopeOffset},
        {         "expensive",                                                     false}
    });
    scopes.push_back({
        {              "name",                                                  "Globals"},
        {"variablesReference", frameId * dap::kScopeMultiplier + dap::kGlobalsScopeOffset},
        {         "expensive",                                                      false}
    });

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "scopes",
            true,
            {
                {"scopes", scopes}
    }
        )
    );
}

void DAPDebugger::processVariables(int seq, const json& args) {
    int varRef = args.value("variablesReference", 0);

    std::lock_guard<std::mutex> lock(frameMutex_);
    json                        variables = json::array();

    int frameId   = varRef / dap::kScopeMultiplier;
    int scopeType = varRef % dap::kScopeMultiplier;

    // 查找对应的帧
    PyFrameHandle frame = nullptr;
    for (const auto& sf : stackFrames_) {
        if (sf.id == frameId) {
            frame = sf.pyFrame;
            break;
        }
    }

    if (frame) {
        py::FrameInfo info = py::getFrameInfo(frame);
        PyHandle      dict = nullptr;

        if (scopeType == dap::kLocalsScopeOffset) {
            py::frameToLocals(frame);
            info = py::getFrameInfo(frame); // 刷新 locals
            dict = info.locals;
        } else if (scopeType == dap::kGlobalsScopeOffset) {
            dict = info.globals;
        }

        if (dict && py::isDict(dict)) {
            variables = getVariablesFromDict(dict);
        }
    } else if (varRef >= dap::kVariableRefBase) {
        // 处理嵌套变量引用
        auto it = variableRefs_.find(varRef);
        if (it != variableRefs_.end()) {
            PyHandle obj = it->second;

            if (py::isDict(obj)) {
                variables = getVariablesFromDict(obj);
            } else if (py::isList(obj)) {
                variables = getVariablesFromList(obj);
            } else if (py::isTuple(obj)) {
                variables = getVariablesFromTuple(obj);
            } else if (py::isModule(obj)) {
                PyHandle dict = py::moduleGetDict(obj);
                if (dict) {
                    variables = getVariablesFromDict(dict);
                }
            } else {
                variables = getVariablesFromObject(obj);
            }
        }
    }

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "variables",
            true,
            {
                {"variables", variables}
    }
        )
    );
}

void DAPDebugger::processContinue(int seq, const json& /*args*/) {
    stepMode_ = StepMode::None;
    state_    = DebuggerState::Running;
    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "continue",
            true,
            {
                {"allThreadsContinued", true}
    }
        )
    );
    notifyCommandReceived();
}

void DAPDebugger::processNext(int seq, const json& /*args*/) {
    stepMode_       = StepMode::Over;
    stepStartFrame_ = currentFrame_;
    stepDepth_      = py::calculateFrameDepth(currentFrame_);
    state_          = DebuggerState::Stepping;

    sendMessage(DAPMessageBuilder::response(seq, "next", true));
    notifyCommandReceived();
}

void DAPDebugger::processStepIn(int seq, const json& /*args*/) {
    stepMode_       = StepMode::Into;
    stepStartFrame_ = currentFrame_;
    state_          = DebuggerState::Stepping;

    sendMessage(DAPMessageBuilder::response(seq, "stepIn", true));
    notifyCommandReceived();
}

void DAPDebugger::processStepOut(int seq, const json& /*args*/) {
    stepMode_       = StepMode::Out;
    stepStartFrame_ = currentFrame_;
    stepDepth_      = py::calculateFrameDepth(currentFrame_);
    state_          = DebuggerState::Stepping;

    sendMessage(DAPMessageBuilder::response(seq, "stepOut", true));
    notifyCommandReceived();
}

void DAPDebugger::processPause(int seq, const json& /*args*/) {
    state_ = DebuggerState::Stopped;
    sendMessage(DAPMessageBuilder::response(seq, "pause", true));
}

void DAPDebugger::processEvaluate(int seq, const json& args) {
    std::string expression = args.value("expression", "");
    int         frameId    = args.value("frameId", 0);

    // 查找对应的帧
    PyFrameHandle frame = nullptr;
    for (const auto& sf : stackFrames_) {
        if (sf.id == frameId) {
            frame = sf.pyFrame;
            break;
        }
    }

    std::string result = "<unable to evaluate>";
    std::string type   = "error";
    int         varRef = 0;

    if (frame) {
        py::frameToLocals(frame);
        py::FrameInfo info    = py::getFrameInfo(frame);
        PyHandle      locals  = info.locals;
        PyHandle      globals = info.globals;

        // 先在 locals/globals 中查找
        PyHandle value = nullptr;
        if (locals && py::isDict(locals)) {
            value = py::dictGetItemString(locals, expression.c_str());
        }
        if (!value && globals && py::isDict(globals)) {
            value = py::dictGetItemString(globals, expression.c_str());
        }

        if (value) {
            result = py::getRepr(value, dap::kMaxEvalResultLength);
            type   = py::getTypeName(value);

            if (py::isExpandable(value)) {
                py::incref(value);
                varRef = registerVariableReference(value);
            }
        } else {
            // 尝试 eval
            py::ObjectGuard code(py::compile(expression.c_str(), "<eval>", py::getEvalInputMode()));
            if (code) {
                py::ObjectGuard evalResult(py::evalCode(code.get(), globals, locals));
                if (evalResult) {
                    result = py::getRepr(evalResult.get(), dap::kMaxEvalResultLength);
                    type   = py::getTypeName(evalResult.get());

                    if (py::isExpandable(evalResult.get())) {
                        varRef = registerVariableReference(evalResult.release());
                    }
                } else {
                    py::clearError();
                }
            } else {
                py::clearError();
            }
        }
    }

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "evaluate",
            true,
            {
                {            "result", result},
                {              "type",   type},
                {"variablesReference", varRef}
    }
        )
    );
}

void DAPDebugger::processDisconnect(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "disconnect", true));
    state_ = DebuggerState::Terminated;
    notifyCommandReceived();
}

// ============== 断点管理 ==============

int DAPDebugger::setBreakpoint(const std::string& source, int line, const std::string& condition) {
    // 注册路径映射，用于将模块路径转换回文件路径
    PathUtils::registerPathMapping(source);

    std::lock_guard<std::mutex> lock(breakpointMutex_);

    Breakpoint bp;
    bp.id        = nextBreakpointId_++;
    bp.source    = source;
    bp.line      = line;
    bp.verified  = true;
    bp.condition = condition;

    breakpoints_[source].push_back(bp);

    std::cout << "[DAP] Breakpoint " << bp.id << " set at " << source << ":" << line << std::endl;
    return bp.id;
}

void DAPDebugger::clearBreakpoints(const std::string& source) {
    std::lock_guard<std::mutex> lock(breakpointMutex_);
    breakpoints_[source].clear();
}

bool DAPDebugger::hasBreakpoint(const std::string& source, int line) {
    std::lock_guard<std::mutex> lock(breakpointMutex_);

    for (const auto& [bpSource, bpList] : breakpoints_) {
        if (PathUtils::matches(bpSource, source)) {
            for (const auto& bp : bpList) {
                if (bp.line == line) return true;
            }
        }
    }
    return false;
}

bool DAPDebugger::hasBreakpoint(const std::string& source) {
    std::lock_guard<std::mutex> lock(breakpointMutex_);

    for (const auto& [bpSource, bpList] : breakpoints_) {
        if (PathUtils::matches(bpSource, source)) {
            if (!bpList.empty()) return true;
        }
    }
    return false;
}

// ============== 变量处理 ==============

int DAPDebugger::registerVariableReference(PyHandle obj) {
    int ref            = dap::kVariableRefBase + nextVarRef_++;
    variableRefs_[ref] = obj;
    return ref;
}

json DAPDebugger::extractVariable(const std::string& name, PyHandle value) {
    std::string valueStr = py::getRepr(value);
    std::string typeStr  = py::getTypeName(value);

    int childRef = 0;
    if (py::isExpandable(value)) {
        py::incref(value);
        childRef = registerVariableReference(value);
    }

    return {
        {              "name",     name},
        {             "value", valueStr},
        {              "type",  typeStr},
        {"variablesReference", childRef}
    };
}

json DAPDebugger::getVariablesFromDict(PyHandle dict) {
    json      variables = json::array();
    long long pos       = 0;
    PyHandle  key       = nullptr;
    PyHandle  value     = nullptr;
    int       count     = 0;

    while (py::dictNext(dict, &pos, &key, &value) && count < dap::kMaxVariables) {
        std::string keyStr;
        if (py::isString(key)) {
            keyStr = py::asString(key);
        } else {
            keyStr = py::getRepr(key);
        }

        variables.push_back(extractVariable(keyStr, value));
        count++;
    }
    return variables;
}

json DAPDebugger::getVariablesFromList(PyHandle list) {
    json      variables = json::array();
    long long size      = py::listSize(list);

    for (long long i = 0; i < size && i < dap::kMaxVariables; i++) {
        PyHandle item = py::listGetItem(list, i);
        variables.push_back(extractVariable(fmt::format("[{}]", i), item));
    }
    return variables;
}

json DAPDebugger::getVariablesFromTuple(PyHandle tuple) {
    json      variables = json::array();
    long long size      = py::tupleSize(tuple);

    for (long long i = 0; i < size && i < dap::kMaxVariables; i++) {
        PyHandle item = py::tupleGetItem(tuple, i);
        variables.push_back(extractVariable(fmt::format("[{}]", i), item));
    }
    return variables;
}

json DAPDebugger::getVariablesFromObject(PyHandle obj) {
    json variables = json::array();

    py::ObjectGuard dirList(py::dir(obj));
    if (!dirList || !py::isList(dirList.get())) {
        return variables;
    }

    long long size  = py::listSize(dirList.get());
    int       count = 0;

    for (long long i = 0; i < size && count < dap::kMaxVariables; i++) {
        PyHandle attrName = py::listGetItem(dirList.get(), i);
        if (!attrName || !py::isString(attrName)) continue;

        std::string nameStr = py::asString(attrName);
        if (nameStr.empty()) continue;

        py::ObjectGuard attrValue(py::getAttr(obj, attrName));
        if (!attrValue) {
            py::clearError();
            continue;
        }

        std::string valueStr = py::getRepr(attrValue.get());
        std::string typeStr  = py::getTypeName(attrValue.get());

        int childRef = 0;
        if (py::isExpandable(attrValue.get())) {
            childRef = registerVariableReference(attrValue.release());
        }

        variables.push_back({
            {              "name",  nameStr},
            {             "value", valueStr},
            {              "type",  typeStr},
            {"variablesReference", childRef}
        });
        count++;
    }

    return variables;
}

// ============== 同步 ==============

void DAPDebugger::waitForCommand() {
    std::unique_lock<std::mutex> lock(commandMutex_);
    commandReceived_ = false;
    commandCV_.wait(lock, [this] { return commandReceived_.load(); });
}

void DAPDebugger::notifyCommandReceived() {
    {
        std::lock_guard<std::mutex> lock(commandMutex_);
        commandReceived_ = true;
    }
    commandCV_.notify_all();
}

// ============== Python 钩子 ==============

void DAPDebugger::onFrameEnter(PyFrameHandle frame) {
    cachedFrame_       = frame;
    py::FrameInfo info = py::getFrameInfo(frame);
    cachedFilename_    = info.filename;
}

void DAPDebugger::onLineExecute(PyFrameHandle frame, int line) {
    if (state_ == DebuggerState::Terminated || state_ == DebuggerState::Disconnected) {
        return;
    }
    std::string source;
    if (frame == cachedFrame_) {
        source = cachedFilename_;
    } else {
        py::FrameInfo info = py::getFrameInfo(frame);
        source             = info.filename;
        cachedFrame_       = frame;
        cachedFilename_    = source;
    }

    std::cout << "[DAP] Executing " << source << ":" << line << std::endl;

    bool        shouldStop = false;
    std::string stopReason;

    // 检查断点
    if (hasBreakpoint(source, line)) {
        shouldStop = true;
        stopReason = "breakpoint";
    }

    // 检查单步执行
    if (state_ == DebuggerState::Stepping) {
        int currentDepth = py::calculateFrameDepth(frame);

        switch (stepMode_) {
        case StepMode::Into:
            shouldStop = true;
            stopReason = "step";
            break;
        case StepMode::Over:
            if (currentDepth <= stepDepth_) {
                shouldStop = true;
                stopReason = "step";
            }
            break;
        case StepMode::Out:
            if (currentDepth < stepDepth_) {
                shouldStop = true;
                stopReason = "step";
            }
            break;
        default:
            break;
        }
    }

    if (!shouldStop) return;

    // 停止执行
    state_         = DebuggerState::Stopped;
    currentFrame_  = frame;
    currentLine_   = line;
    currentSource_ = source;
    stepMode_      = StepMode::None;

    // 清除旧的变量引用
    for (auto& [ref, obj] : variableRefs_) {
        py::xdecref(obj);
    }
    variableRefs_.clear();
    nextVarRef_ = 1;

    // 构建堆栈帧
    {
        std::lock_guard<std::mutex> lock(frameMutex_);
        stackFrames_.clear();

        PyFrameHandle f   = frame;
        int           idx = 0;
        while (f && idx < dap::kMaxStackFrames) {
            py::FrameInfo finfo = py::getFrameInfo(f);

            StackFrame sf;
            sf.id      = nextFrameId_++;
            sf.pyFrame = f;
            sf.line    = finfo.lineNumber;
            sf.column  = 1;
            sf.name    = finfo.funcName;
            // 将模块路径转换为文件系统路径，以便 VSCode 能正确打开源文件
            sf.source = PathUtils::resolveToFilePath(finfo.filename);

            stackFrames_.push_back(sf);
            f = finfo.back;
            idx++;
        }
    }

    // 发送 stopped 事件
    sendMessage(
        DAPMessageBuilder::event(
            "stopped",
            {
                {           "reason", stopReason},
                {         "threadId",          1},
                {"allThreadsStopped",       true}
    }
        )
    );

    std::cout << "[DAP] Stopped at " << source << ":" << line << " (" << stopReason << ")" << std::endl;

    // 等待调试命令
    waitForCommand();
}

void DAPDebugger::onFrameExit(PyFrameHandle frame) {
    // 清除缓存（如果退出的是缓存的帧）
    if (frame == cachedFrame_) {
        cachedFrame_ = nullptr;
        cachedFilename_.clear();
    }
}

// ============== 全局访问 ==============

DAPDebugger& getDebugger() { return DAPDebugger::getInstance(); }
