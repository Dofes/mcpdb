#include "Debugger.h"

#include <fmt/format.h>

#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

namespace path_utils {

// 路径映射表：模块路径 -> 文件系统路径
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

void clearPathMapping() {
    std::lock_guard<std::mutex> lock(g_pathMappingMutex);
    g_pathMapping.clear();
}

bool matches(const std::string& breakpointPath, const std::string& sourcePath) {
    std::string bp  = normalize(breakpointPath);
    std::string src = normalize(sourcePath);

    if (bp == src) return true;

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

} // namespace path_utils

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

json DAPMessageBuilder::response(
    int                requestSeq,
    const std::string& command,
    bool               success,
    const json&        body,
    const std::string& message
) {
    json resp = {
        {        "seq",  nextSeq()},
        {       "type", "response"},
        {"request_seq", requestSeq},
        {    "success",    success},
        {    "command",    command}
    };
    if (!message.empty()) {
        resp["message"] = message;
    }
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
    mState = DebuggerState::Initializing;
    startServer(port);
    return true;
}

void DAPDebugger::shutdown() {
    mState = DebuggerState::Disconnected;
    stopServer();
}

void DAPDebugger::startServer(int port) {
    if (mServerRunning) return;

    mServerRunning = true;
    mServerStarted = false;

    std::unique_lock<std::mutex> startLock(mServerStartMutex);

    mServerThread = std::thread([this, port]() {
        auto notifyStarted = [this](bool success) {
            {
                std::lock_guard<std::mutex> lock(mServerStartMutex);
                mServerStarted = success;
            }
            mServerStartCv.notify_all();
        };

        mServerSocket = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (mServerSocket < 0) {
            std::cerr << "[DAP] Failed to create socket" << std::endl;
            std::cerr.flush();
            notifyStarted(false);
            return;
        }

        int opt = 1;
        setsockopt(mServerSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(static_cast<u_short>(port));

        if (bind(mServerSocket, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "[DAP] Failed to bind to port " << port << std::endl;
            std::cerr.flush();
            closesocket(mServerSocket);
            notifyStarted(false);
            return;
        }

        listen(mServerSocket, 1);
        std::cout << "[DAP] Debug adapter listening on port " << port << std::endl;
        std::cout.flush();
        notifyStarted(true);

        while (mServerRunning) {
            sockaddr_in clientAddr{};
            socklen_t   clientLen = sizeof(clientAddr);
            mClientSocket         = static_cast<int>(accept(mServerSocket, (sockaddr*)&clientAddr, &clientLen));

            if (mClientSocket < 0) continue;

            std::cout << "[DAP] Client connected" << std::endl;
            std::cout.flush();
            mState = DebuggerState::Initializing;

            char        buffer[65536];
            std::string messageBuffer;

            while (mServerRunning && mClientSocket >= 0) {
                int received = recv(mClientSocket, buffer, sizeof(buffer) - 1, 0);
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
            closesocket(mClientSocket);
            mClientSocket = -1;
        }
    });

    // 等待服务器启动完成
    mServerStartCv.wait(startLock, [this] { return mServerStarted.load() || !mServerRunning.load(); });
}

void DAPDebugger::stopServer() {
    mServerRunning = false;
    if (mClientSocket >= 0) {
        closesocket(mClientSocket);
        mClientSocket = -1;
    }
    if (mServerSocket >= 0) {
        closesocket(mServerSocket);
        mServerSocket = -1;
    }
    if (mServerThread.joinable()) {
        mServerThread.join();
    }
}

void DAPDebugger::sendMessage(const json& message) { sendRaw(message.dump()); }

void DAPDebugger::sendRaw(const std::string& message) const {
    if (mClientSocket < 0) return;

    std::string packet = fmt::format("Content-Length: {}\r\n\r\n{}", message.size(), message);
    send(mClientSocket, packet.c_str(), static_cast<int>(packet.size()), 0);
}


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
        } else if (command == "setVariable") {
            processSetVariable(seq, args);
        } else if (command == "completions") {
            processCompletions(seq, args);
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
        { "supportsConfigurationDoneRequest",       true},
        {      "supportsFunctionBreakpoints",      false},
        {   "supportsConditionalBreakpoints",       true},
        {"supportsHitConditionalBreakpoints",      false},
        {        "supportsEvaluateForHovers",       true},
        {                 "supportsStepBack",      false},
        {              "supportsSetVariable",       true},
        {             "supportsRestartFrame",      false},
        {       "supportsGotoTargetsRequest",      false},
        {     "supportsStepInTargetsRequest",      false},
        {       "supportsCompletionsRequest",       true},
        {      "completionTriggerCharacters", {".", "["}},
        {           "supportsModulesRequest",      false},
        {         "supportsExceptionOptions",      false},
        {   "supportsValueFormattingOptions",      false},
        {     "supportsExceptionInfoRequest",      false},
        {         "supportTerminateDebuggee",       true},
        { "supportsDelayedStackTraceLoading",      false},
        {     "supportsLoadedSourcesRequest",      false}
    };

    sendMessage(DAPMessageBuilder::response(seq, "initialize", true, capabilities));
    sendMessage(DAPMessageBuilder::event("initialized"));
}

void DAPDebugger::processLaunch(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "launch", true));
    mState = DebuggerState::Running;
}

void DAPDebugger::processAttach(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "attach", true));
    mState = DebuggerState::Running;
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
                std::string condition = bp.value("condition", "");
                int         bpId      = setBreakpoint(sourcePath, line, condition);
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
    mState = DebuggerState::Running;
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
    std::lock_guard<std::mutex> lock(mFrameMutex);

    json frames = json::array();
    for (const auto& frame : mStackFrames) {
        frames.push_back(frame.toJson());
    }

    sendMessage(
        DAPMessageBuilder::response(
            seq,
            "stackTrace",
            true,
            {
                {"stackFrames",              frames},
                {"totalFrames", mStackFrames.size()}
    }
        )
    );
}

void DAPDebugger::processScopes(int seq, const json& args) {
    int frameId = args.value("frameId", 0);

    int localsRef  = mNextVarRef++;
    int globalsRef = mNextVarRef++;

    mVariableRefs[localsRef]  = {VariableRefType::Locals, frameId, nullptr};
    mVariableRefs[globalsRef] = {VariableRefType::Globals, frameId, nullptr};

    json scopes = json::array();
    scopes.push_back({
        {              "name",  "Locals"},
        {"variablesReference", localsRef},
        {         "expensive",     false}
    });
    scopes.push_back({
        {              "name",  "Globals"},
        {"variablesReference", globalsRef},
        {         "expensive",      false}
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

    json variables = json::array();

    VariableRef ref;
    {
        std::lock_guard<std::mutex> lock(mFrameMutex);
        auto                        it = mVariableRefs.find(varRef);
        if (it == mVariableRefs.end()) {
            sendMessage(
                DAPMessageBuilder::response(
                    seq,
                    "variables",
                    false,
                    {
                        {"message", "Variable reference no longer valid."}
            }
                )
            );
            return;
        }
        ref = it->second;
    }

    // Locals/Globals 只在 Stopped 状态可用
    if ((ref.type == VariableRefType::Locals || ref.type == VariableRefType::Globals)
        && mState != DebuggerState::Stopped) {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "variables",
                false,
                {
                    {"message", "Cannot access frame variables while running."}
        }
            )
        );
        return;
    }

    if (mState == DebuggerState::Stopped) {
        // 提交任务到主线程执行
        auto completion = std::make_shared<std::promise<void>>();
        auto future     = completion->get_future();

        {
            std::lock_guard<std::mutex> lock(mTaskQueueMutex);
            mTaskQueue.push(
                {[this, &ref, &variables]() {
                     switch (ref.type) {
                     case VariableRefType::Locals:
                     case VariableRefType::Globals: {
                         PyFrameHandle frame = nullptr;
                         {
                             std::lock_guard<std::mutex> flock(mFrameMutex);
                             for (const auto& sf : mStackFrames) {
                                 if (sf.id == ref.frameId) {
                                     frame = sf.pyFrame;
                                     break;
                                 }
                             }
                         }

                         if (frame) {
                             py::FrameInfo info = py::getFrameInfo(frame);
                             PyHandle      dict = nullptr;

                             if (ref.type == VariableRefType::Locals) {
                                 py::frameToLocals(frame);
                                 info = py::getFrameInfo(frame);
                                 dict = info.locals;
                             } else {
                                 dict = info.globals;
                             }

                             if (dict && py::isDict(dict)) {
                                 variables = getVariablesFromDict(dict);
                             }
                         }
                         break;
                     }
                     case VariableRefType::Object: {
                         PyHandle obj = ref.object;
                         if (obj) {
                             if (py::isDict(obj)) {
                                 variables = getVariablesFromDict(obj);
                             } else if (py::isList(obj)) {
                                 variables = getVariablesFromList(obj);
                             } else if (py::isTuple(obj)) {
                                 variables = getVariablesFromTuple(obj);
                             } else if (py::isSet(obj)) {
                                 variables = getVariablesFromSet(obj);
                             } else if (py::isModule(obj)) {
                                 PyHandle dict = py::moduleGetDict(obj);
                                 if (dict) {
                                     variables = getVariablesFromDict(dict);
                                 }
                             } else {
                                 variables = getVariablesFromObject(obj);
                             }
                         }
                         break;
                     }
                     }
                 },
                 completion}
            );
        }
        mTaskQueueCv.notify_one();
        future.wait();
    } else {
        // Running 状态，Object 类型需要获取 GIL
        if (ref.type == VariableRefType::Object) {
            py::GILGuard gil;
            PyHandle     obj = ref.object;
            if (obj) {
                if (py::isDict(obj)) {
                    variables = getVariablesFromDict(obj);
                } else if (py::isList(obj)) {
                    variables = getVariablesFromList(obj);
                } else if (py::isTuple(obj)) {
                    variables = getVariablesFromTuple(obj);
                } else if (py::isSet(obj)) {
                    variables = getVariablesFromSet(obj);
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

void DAPDebugger::clearVariableReferences() {
    for (auto& [id, ref] : mVariableRefs) {
        if (ref.type == VariableRefType::Object && ref.object) {
            py::xdecref(ref.object);
        }
    }
    mVariableRefs.clear();
    mNextVarRef = 1;
}

void DAPDebugger::processContinue(int seq, const json& /*args*/) {
    mStepMode = StepMode::None;
    mState    = DebuggerState::Running;
    clearVariableReferences();
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
    mStepMode       = StepMode::Over;
    mStepStartFrame = mCurrentFrame;
    mStepDepth      = py::calculateFrameDepth(mCurrentFrame);
    mState          = DebuggerState::Stepping;
    clearVariableReferences();

    sendMessage(DAPMessageBuilder::response(seq, "next", true));
    notifyCommandReceived();
}

void DAPDebugger::processStepIn(int seq, const json& /*args*/) {
    mStepMode       = StepMode::Into;
    mStepStartFrame = mCurrentFrame;
    mState          = DebuggerState::Stepping;
    clearVariableReferences();

    sendMessage(DAPMessageBuilder::response(seq, "stepIn", true));
    notifyCommandReceived();
}

void DAPDebugger::processStepOut(int seq, const json& /*args*/) {
    mStepMode       = StepMode::Out;
    mStepStartFrame = mCurrentFrame;
    mStepDepth      = py::calculateFrameDepth(mCurrentFrame);
    mState          = DebuggerState::Stepping;
    clearVariableReferences();

    sendMessage(DAPMessageBuilder::response(seq, "stepOut", true));
    notifyCommandReceived();
}

void DAPDebugger::processPause(int seq, const json& /*args*/) {
    mState = DebuggerState::Stopped;
    sendMessage(DAPMessageBuilder::response(seq, "pause", true));
}

void DAPDebugger::processEvaluate(int seq, const json& args) {
    std::string expression = args.value("expression", "");
    std::string context    = args.value("context", "");
    bool        isRepl     = (context == "repl");
    bool        isHover    = (context == "hover");

    if (isHover && !expression.empty() && expression[0] == '.') {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "evaluate",
                false,
                {
                    {"message", "Cannot evaluate partial expression"}
        }
            )
        );
        return;
    }

    std::string result;
    std::string type;
    int         varRef  = 0;
    bool        isError = false;

    // 如果调试器已暂停，提交任务到主线程执行
    if (mState == DebuggerState::Stopped) {
        // 创建完成通知
        auto completion = std::make_shared<std::promise<void>>();
        auto future     = completion->get_future();

        // 获取 frame（在当前线程安全获取）
        PyFrameHandle frame = nullptr;
        {
            std::lock_guard<std::mutex> lock(mFrameMutex);

            if (args.contains("frameId")) {
                int frameId = args["frameId"].get<int>();
                for (const auto& sf : mStackFrames) {
                    if (sf.id == frameId) {
                        frame = sf.pyFrame;
                        break;
                    }
                }
            }

            if (!frame) {
                if (mCurrentFrame) {
                    frame = mCurrentFrame;
                } else if (!mStackFrames.empty()) {
                    frame = mStackFrames.front().pyFrame;
                }
            }
        }

        if (!frame) {
            sendMessage(
                DAPMessageBuilder::response(
                    seq,
                    "evaluate",
                    false,
                    {
                        {"error", {{"id", seq}, {"format", "No frame available"}, {"showUser", false}}}
            },
                    "No frame available"
                )
            );
            return;
        }

        // 提交任务到主线程
        {
            std::lock_guard<std::mutex> lock(mTaskQueueMutex);
            mTaskQueue.push(
                {[this, frame, expression, isRepl, &result, &type, &varRef, &isError]() {
                     // 这个 lambda 在主线程执行
                     py::frameToLocals(frame);
                     py::FrameInfo info    = py::getFrameInfo(frame);
                     PyHandle      locals  = info.locals;
                     PyHandle      globals = info.globals;

                     if (isRepl) {
                         auto replResult = py::execREPL(expression.c_str(), globals, locals);
                         result          = replResult.output;
                         isError         = replResult.isError;
                         type            = replResult.resultType;
                         // 如果有结果对象且可展开，注册变量引用
                         if (replResult.resultObject && py::isExpandable(replResult.resultObject)) {
                             varRef = registerVariableReference(replResult.resultObject);
                         } else if (replResult.resultObject) {
                             py::decref(replResult.resultObject);
                         }
                         py::localsToFast(frame);
                     } else {
                         PyHandle value = nullptr;
                         if (locals && py::isDict(locals)) {
                             value = py::dictGetItemString(locals, expression.c_str());
                         }
                         if (!value && globals && py::isDict(globals)) {
                             value = py::dictGetItemString(globals, expression.c_str());
                         }

                         if (value) {
                             result = py::getRepr(value, dap::MaxEvalResultLength);
                             type   = py::getTypeName(value);
                             if (py::isExpandable(value)) {
                                 py::incref(value);
                                 varRef = registerVariableReference(value);
                             }
                         } else {
                             py::ObjectGuard code(py::compile(expression.c_str(), "<eval>", py::getEvalInputMode()));
                             if (code) {
                                 py::ObjectGuard evalResult(py::evalCode(code.get(), globals, locals));
                                 if (evalResult) {
                                     result = py::getRepr(evalResult.get(), dap::MaxEvalResultLength);
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
                 },
                 completion}
            );
        }
        mTaskQueueCv.notify_one();

        // 等待主线程执行完毕
        future.wait();
    } else {
        // 调试器运行中，需要获取 GIL 才能安全执行 Python 代码
        py::GILGuard gil;

        PyHandle mainModule = py::importAddModule("__main__");
        PyHandle globals    = mainModule ? py::moduleGetDict(mainModule) : nullptr;

        if (globals && py::isDict(globals)) {
            if (isRepl) {
                auto replResult = py::execREPL(expression.c_str(), globals, globals);
                result          = replResult.output;
                isError         = replResult.isError;
                type            = replResult.resultType;
                // 如果有结果对象且可展开，注册变量引用
                if (replResult.resultObject && py::isExpandable(replResult.resultObject)) {
                    varRef = registerVariableReference(replResult.resultObject);
                } else if (replResult.resultObject) {
                    py::decref(replResult.resultObject);
                }
            } else {
                PyHandle value = py::dictGetItemString(globals, expression.c_str());

                if (value) {
                    result = py::getRepr(value, dap::MaxEvalResultLength);
                    type   = py::getTypeName(value);
                    if (py::isExpandable(value)) {
                        py::incref(value);
                        varRef = registerVariableReference(value);
                    }
                } else {
                    py::ObjectGuard code(py::compile(expression.c_str(), "<eval>", py::getEvalInputMode()));
                    if (code) {
                        py::ObjectGuard evalResult(py::evalCode(code.get(), globals, globals));
                        if (evalResult) {
                            result = py::getRepr(evalResult.get(), dap::MaxEvalResultLength);
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
        }
    }

    if (isHover && result.empty()) {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "evaluate",
                false,
                {
                    {"message", "Cannot evaluate expression"}
        }
            )
        );
        return;
    }

    if (isError && isRepl) {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "evaluate",
                false,
                {
                    {"error", {{"id", seq}, {"format", result}, {"showUser", false}}}
        },
                result
            )
        );
    } else {
        std::cout << "[DAP] Eval result: " << result << std::endl;
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
}

void DAPDebugger::processSetVariable(int seq, const json& args) {
    int         varRef = args.value("variablesReference", 0);
    std::string name   = args.value("name", "");
    std::string value  = args.value("value", "");

    if (mState != DebuggerState::Stopped) {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "setVariable",
                false,
                {
                    {"message", "Cannot set variable while running."}
        }
            )
        );
        return;
    }

    // 结果变量
    bool        success = false;
    std::string errorMsg;
    std::string resultStr;
    std::string typeStr;
    int         newVarRef = 0;

    // 创建完成通知
    auto completion = std::make_shared<std::promise<void>>();
    auto future     = completion->get_future();

    // 提交任务到主线程执行
    {
        std::lock_guard<std::mutex> lock(mTaskQueueMutex);
        mTaskQueue.push(
            {[this, varRef, name, value, &success, &errorMsg, &resultStr, &typeStr, &newVarRef]() {
                 std::lock_guard<std::mutex> frameLock(mFrameMutex);

                 auto it = mVariableRefs.find(varRef);
                 if (it == mVariableRefs.end()) {
                     errorMsg = "Invalid variable reference.";
                     return;
                 }

                 const VariableRef& ref        = it->second;
                 PyHandle           targetDict = nullptr;
                 PyFrameHandle      frame      = nullptr;

                 // 获取目标字典
                 switch (ref.type) {
                 case VariableRefType::Locals:
                 case VariableRefType::Globals: {
                     for (const auto& sf : mStackFrames) {
                         if (sf.id == ref.frameId) {
                             frame = sf.pyFrame;
                             break;
                         }
                     }
                     if (frame) {
                         py::frameToLocals(frame);
                         py::FrameInfo info = py::getFrameInfo(frame);
                         targetDict         = (ref.type == VariableRefType::Locals) ? info.locals : info.globals;
                     }
                     break;
                 }
                 case VariableRefType::Object: {
                     if (py::isDict(ref.object)) {
                         targetDict = ref.object;
                     }
                     break;
                 }
                 }

                 if (!targetDict || !py::isDict(targetDict)) {
                     errorMsg = "Cannot modify this variable container.";
                     return;
                 }

                 // 编译并执行新值表达式
                 py::ObjectGuard code(py::compile(value.c_str(), "<setvar>", py::getEvalInputMode()));
                 if (!code) {
                     py::clearError();
                     errorMsg = "Invalid value expression.";
                     return;
                 }

                 // 获取用于求值的 globals
                 PyHandle evalGlobals = targetDict;
                 if (frame) {
                     py::FrameInfo info = py::getFrameInfo(frame);
                     evalGlobals        = info.globals;
                 }

                 py::ObjectGuard newValue(py::evalCode(code.get(), evalGlobals, targetDict));
                 if (!newValue) {
                     py::clearError();
                     errorMsg = "Failed to evaluate value expression.";
                     return;
                 }

                 // 设置新值
                 if (py::dictSetItemString(targetDict, name.c_str(), newValue.get()) != 0) {
                     py::clearError();
                     errorMsg = "Failed to set variable.";
                     return;
                 }

                 // 如果是修改 frame 的 locals，同步回 fast locals
                 if (frame && ref.type == VariableRefType::Locals) {
                     py::localsToFast(frame);
                 }

                 // 返回新值信息
                 resultStr = py::getRepr(newValue.get(), dap::MaxEvalResultLength);
                 typeStr   = py::getTypeName(newValue.get());

                 if (py::isExpandable(newValue.get())) {
                     newVarRef = registerVariableReference(newValue.release());
                 }

                 success = true;
             },
             completion}
        );
    }
    mTaskQueueCv.notify_one();

    // 等待任务完成
    future.wait();

    // 发送响应
    if (success) {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "setVariable",
                true,
                {
                    {             "value", resultStr},
                    {              "type",   typeStr},
                    {"variablesReference", newVarRef}
        }
            )
        );
    } else {
        sendMessage(
            DAPMessageBuilder::response(
                seq,
                "setVariable",
                false,
                {
                    {"message", errorMsg}
        }
            )
        );
    }
}

void DAPDebugger::processCompletions(int seq, const json& args) {
    std::string text   = args.value("text", "");
    int         column = args.value("column", 0); // 1-based by default in DAP
    int         line   = args.value("line", 1);

    json targets = json::array();

    int cursorPos = column - 1;
    if (cursorPos < 0) cursorPos = 0;
    if (cursorPos > static_cast<int>(text.size())) cursorPos = static_cast<int>(text.size());

    std::string prefix = text.substr(0, cursorPos);

    size_t dotPos     = prefix.rfind('.');
    size_t identStart = prefix.find_last_of(" \t\n\r(,=[{:+-*/%<>!&|^~");
    if (identStart == std::string::npos) {
        identStart = 0;
    } else {
        identStart++;
    }

    std::string completionPrefix;
    int         replaceStart  = 0; // 0-based position where replacement starts
    int         replaceLength = 0; // how many characters to replace
    PyHandle    targetObj     = nullptr;
    bool        needDecref    = false;

    if (dotPos != std::string::npos && dotPos >= identStart) {
        std::string objExpr = prefix.substr(identStart, dotPos - identStart);
        completionPrefix    = prefix.substr(dotPos + 1);
        replaceStart        = static_cast<int>(dotPos + 1);
        replaceLength       = static_cast<int>(completionPrefix.size());

        if (mState == DebuggerState::Stopped) {
            PyFrameHandle frame   = nullptr;
            PyHandle      globals = nullptr;
            PyHandle      locals  = nullptr;

            {
                std::lock_guard<std::mutex> lock(mFrameMutex);
                if (mCurrentFrame) {
                    frame = mCurrentFrame;
                } else if (!mStackFrames.empty()) {
                    frame = mStackFrames.front().pyFrame;
                }
            }

            if (frame) {
                py::frameToLocals(frame);
                py::FrameInfo info = py::getFrameInfo(frame);
                locals             = info.locals;
                globals            = info.globals;

                if (globals) {
                    py::ObjectGuard code(py::compile(objExpr.c_str(), "<completion>", py::getEvalInputMode()));
                    if (code) {
                        PyHandle result = py::evalCode(code.get(), globals, locals ? locals : globals);
                        if (result) {
                            targetObj  = result;
                            needDecref = true;
                        }
                    }
                    py::clearError();
                }
            }
        } else {
            py::GILGuard gil;
            PyHandle     mainModule = py::importAddModule("__main__");
            PyHandle     globals    = mainModule ? py::moduleGetDict(mainModule) : nullptr;

            if (globals) {
                py::ObjectGuard code(py::compile(objExpr.c_str(), "<completion>", py::getEvalInputMode()));
                if (code) {
                    PyHandle result = py::evalCode(code.get(), globals, globals);
                    if (result) {
                        targetObj  = result;
                        needDecref = true;
                    }
                }
                py::clearError();
            }

            if (targetObj) {
                auto completions = py::getCompletions(targetObj, completionPrefix);
                for (const auto& name : completions) {
                    std::string type = "property";
                    if (name.find("__") == 0) {
                        type = "keyword";
                    }
                    targets.push_back({
                        { "label",             name},
                        {  "type",             type},
                        { "start", replaceStart + 1},
                        {"length",    replaceLength}
                    });
                }

                if (needDecref) {
                    py::decref(targetObj);
                }
                targetObj = nullptr;
            }
        }
    } else {
        completionPrefix = prefix.substr(identStart);
        replaceStart     = static_cast<int>(identStart);
        replaceLength    = static_cast<int>(completionPrefix.size());

        static const std::vector<std::string> keywords = {
            "and",  "as",      "assert", "break", "class",  "continue", "def",    "del",  "elif", "else",   "except",
            "exec", "finally", "for",    "from",  "global", "if",       "import", "in",   "is",   "lambda", "not",
            "or",   "pass",    "print",  "raise", "return", "try",      "while",  "with", "yield"
        };

        auto addKeywords = [&](int& sortIndex) {
            for (const auto& kw : keywords) {
                if (completionPrefix.empty() || kw.find(completionPrefix) == 0) {
                    targets.push_back({
                        { "label",               kw},
                        {  "type",        "keyword"},
                        { "start", replaceStart + 1},
                        {"length",    replaceLength}
                    });
                    sortIndex++;
                }
            }
        };

        auto addBuiltins = [&](int& sortIndex) {
            PyHandle mainModule = py::importAddModule("__main__");
            if (!mainModule) return;

            PyHandle mainDir = py::dir(mainModule);
            if (!mainDir || !py::isList(mainDir)) return;

            PyHandle  builtins    = nullptr;
            long long mainDirSize = py::listSize(mainDir);
            for (long long i = 0; i < mainDirSize; i++) {
                PyHandle attrName = py::listGetItem(mainDir, i);
                if (attrName && py::isString(attrName) && py::asString(attrName) == "__builtins__") {
                    builtins = py::getAttr(mainModule, attrName);
                    break;
                }
            }
            py::decref(mainDir);

            if (!builtins) return;

            PyHandle builtinsDir = py::dir(builtins);
            if (builtinsDir && py::isList(builtinsDir)) {
                long long size = py::listSize(builtinsDir);
                for (long long i = 0; i < size; i++) {
                    PyHandle attrName = py::listGetItem(builtinsDir, i);
                    if (!attrName || !py::isString(attrName)) continue;

                    std::string name = py::asString(attrName);
                    if (!name.empty() && name[0] == '_' && name != "__import__") continue;
                    if (!completionPrefix.empty() && name.find(completionPrefix) != 0) continue;

                    PyHandle    value = py::getAttr(builtins, attrName);
                    std::string type  = (value && py::isType(value)) ? "class" : "function";
                    if (value) py::decref(value);

                    targets.push_back({
                        { "label",             name},
                        {  "type",             type},
                        { "start", replaceStart + 1},
                        {"length",    replaceLength}
                    });
                }
                py::decref(builtinsDir);
            }
            py::decref(builtins);
            py::clearError();
        };

        if (mState == DebuggerState::Stopped) {
            std::lock_guard<std::mutex> lock(mFrameMutex);
            PyFrameHandle               frame = nullptr;
            if (mCurrentFrame) {
                frame = mCurrentFrame;
            } else if (!mStackFrames.empty()) {
                frame = mStackFrames.front().pyFrame;
            }

            int sortIndex = 0;

            if (frame) {
                py::frameToLocals(frame);
                py::FrameInfo info = py::getFrameInfo(frame);

                // 从 locals 收集
                if (info.locals) {
                    auto keys = py::getDictKeys(info.locals);
                    for (const auto& key : keys) {
                        if (completionPrefix.empty() || key.find(completionPrefix) == 0) {
                            targets.push_back({
                                { "label",              key},
                                {  "type",       "variable"},
                                { "start", replaceStart + 1},
                                {"length",    replaceLength}
                            });
                        }
                    }
                }

                // 从 globals 收集
                if (info.globals && info.globals != info.locals) {
                    auto keys = py::getDictKeys(info.globals);
                    for (const auto& key : keys) {
                        if (completionPrefix.empty() || key.find(completionPrefix) == 0) {
                            targets.push_back({
                                { "label",              key},
                                {  "type",       "variable"},
                                { "start", replaceStart + 1},
                                {"length",    replaceLength}
                            });
                        }
                    }
                }
            }

            addKeywords(sortIndex);

            if (frame) {
                addBuiltins(sortIndex);
            }
        } else {
            py::GILGuard gil;
            PyHandle     mainModule = py::importAddModule("__main__");
            PyHandle     globals    = mainModule ? py::moduleGetDict(mainModule) : nullptr;

            if (globals) {
                auto keys = py::getDictKeys(globals);
                for (const auto& key : keys) {
                    if (completionPrefix.empty() || key.find(completionPrefix) == 0) {
                        targets.push_back({
                            { "label",              key},
                            {  "type",       "variable"},
                            { "start", replaceStart + 1},
                            {"length",    replaceLength}
                        });
                    }
                }
            }

            int sortIndex = 0;
            addKeywords(sortIndex);
            addBuiltins(sortIndex);
        }
    }

    if (targetObj) {
        auto completions = py::getCompletions(targetObj, completionPrefix);
        for (const auto& name : completions) {
            std::string type = "property";
            if (name.find("__") == 0) {
                type = "keyword";
            }
            targets.push_back({
                { "label",             name},
                {  "type",             type},
                { "start", replaceStart + 1},
                {"length",    replaceLength}
            });
        }

        if (needDecref) {
            py::decref(targetObj);
        }
    }

    json response = DAPMessageBuilder::response(
        seq,
        "completions",
        true,
        {
            {"targets", targets}
    }
    );

    std::cout << "[Completions] Response: " << response.dump() << std::endl;

    sendMessage(response);
}

void DAPDebugger::processDisconnect(int seq, const json& /*args*/) {
    sendMessage(DAPMessageBuilder::response(seq, "disconnect", true));
    mState = DebuggerState::Terminated;
    notifyCommandReceived();
}

int DAPDebugger::setBreakpoint(const std::string& source, int line, const std::string& condition) {
    path_utils::registerPathMapping(source);

    std::lock_guard<std::mutex> lock(mBreakpointMutex);

    Breakpoint bp;
    bp.id        = mNextBreakpointId++;
    bp.source    = source;
    bp.line      = line;
    bp.verified  = true;
    bp.condition = condition;

    mBreakpoints[source].push_back(bp);

    std::cout << "[DAP] Breakpoint " << bp.id << " set at " << source << ":" << line << std::endl;
    return bp.id;
}

void DAPDebugger::clearBreakpoints(const std::string& source) {
    std::lock_guard<std::mutex> lock(mBreakpointMutex);
    mBreakpoints[source].clear();
}

bool DAPDebugger::hasBreakpoint(const std::string& source, int line) {
    std::lock_guard<std::mutex> lock(mBreakpointMutex);

    for (const auto& [bpSource, bpList] : mBreakpoints) {
        if (path_utils::matches(bpSource, source)) {
            for (const auto& bp : bpList) {
                if (bp.line == line) return true;
            }
        }
    }
    return false;
}

bool DAPDebugger::hasBreakpoint(const std::string& source) {
    std::lock_guard<std::mutex> lock(mBreakpointMutex);

    for (const auto& [bpSource, bpList] : mBreakpoints) {
        if (path_utils::matches(bpSource, source)) {
            if (!bpList.empty()) return true;
        }
    }
    return false;
}

bool DAPDebugger::hasBreakpointInCurrentFrame() { return hasBreakpoint(mCachedFilename); }

Breakpoint* DAPDebugger::getBreakpoint(const std::string& source, int line) {
    std::lock_guard<std::mutex> lock(mBreakpointMutex);

    for (auto& [bpSource, bpList] : mBreakpoints) {
        if (path_utils::matches(bpSource, source)) {
            for (auto& bp : bpList) {
                if (bp.line == line) return &bp;
            }
        }
    }
    return nullptr;
}

int DAPDebugger::registerVariableReference(PyHandle obj) {
    int ref            = mNextVarRef++;
    mVariableRefs[ref] = {VariableRefType::Object, 0, obj};
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

    while (py::dictNext(dict, &pos, &key, &value) && count < dap::MaxVariables) {
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

    for (long long i = 0; i < size && i < dap::MaxVariables; i++) {
        PyHandle item = py::listGetItem(list, i);
        variables.push_back(extractVariable(fmt::format("[{}]", i), item));
    }
    return variables;
}

json DAPDebugger::getVariablesFromTuple(PyHandle tuple) {
    json      variables = json::array();
    long long size      = py::tupleSize(tuple);

    for (long long i = 0; i < size && i < dap::MaxVariables; i++) {
        PyHandle item = py::tupleGetItem(tuple, i);
        variables.push_back(extractVariable(fmt::format("[{}]", i), item));
    }
    return variables;
}

json DAPDebugger::getVariablesFromSet(PyHandle set) {
    json      variables = json::array();
    long long pos       = 0;
    PyHandle  key       = nullptr;
    int       index     = 0;

    while (py::setNext(set, &pos, &key) && index < dap::MaxVariables) {
        std::string name = fmt::format("{}", reinterpret_cast<uintptr_t>(key));
        variables.push_back(extractVariable(name, key));
        ++index;
    }

    long long size = py::setSize(set);
    variables.push_back({
        {              "name",              "len()"},
        {             "value", std::to_string(size)},
        {"variablesReference",                    0}
    });

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

    for (long long i = 0; i < size && count < dap::MaxVariables; i++) {
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

void DAPDebugger::waitForCommand() { debuggerLoop(); }

void DAPDebugger::debuggerLoop() {
    // 主线程在断点处调用此函数，循环处理来自调试器线程的任务
    mShouldContinue = false;

    while (!mShouldContinue.load()) {
        std::unique_lock<std::mutex> lock(mTaskQueueMutex);

        mTaskQueueCv.wait(lock, [this] { return !mTaskQueue.empty() || mShouldContinue.load(); });

        if (mShouldContinue.load()) {
            break;
        }

        if (!mTaskQueue.empty()) {
            auto pendingTask = std::move(mTaskQueue.front());
            mTaskQueue.pop();
            lock.unlock();

            pendingTask.task();

            if (pendingTask.completion) {
                pendingTask.completion->set_value();
            }
        }
    }
}

void DAPDebugger::notifyCommandReceived() {
    // 设置继续标志并唤醒主线程
    mShouldContinue = true;
    mTaskQueueCv.notify_all();
}

void DAPDebugger::onFrameEnter(PyFrameHandle frame) {
    mCachedFrame       = frame;
    py::FrameInfo info = py::getFrameInfo(frame);
    mCachedFilename    = info.filename;
}

void DAPDebugger::onLineExecute(PyFrameHandle frame, int line) {
    if (mState == DebuggerState::Terminated || mState == DebuggerState::Disconnected) {
        return;
    }

    std::string source;
    if (frame == mCachedFrame) {
        source = mCachedFilename;
    } else {
        py::FrameInfo info = py::getFrameInfo(frame);
        source             = info.filename;
        mCachedFrame       = frame;
        mCachedFilename    = source;
    }

    bool        shouldStop = false;
    std::string stopReason;

    // 检查断点
    Breakpoint* bp = getBreakpoint(source, line);
    if (bp) {
        bool conditionMet = true;

        // 如果有条件，评估条件表达式
        if (!bp->condition.empty()) {
            py::frameToLocals(frame);
            py::FrameInfo info = py::getFrameInfo(frame);

            py::ObjectGuard code(py::compile(bp->condition.c_str(), "<breakpoint condition>", py::getEvalInputMode()));
            if (code) {
                py::ObjectGuard result(py::evalCode(code.get(), info.globals, info.locals));
                if (result) {
                    if (py::isNone(result.get())) {
                        conditionMet = false;
                    } else if (py::isBool(result.get())) {
                        std::string repr = py::toString(result.get());
                        conditionMet     = (repr == "True");
                    } else if (py::isInt(result.get()) || py::isLong(result.get())) {
                        std::string valueStr = py::toString(result.get());
                        conditionMet         = (valueStr != "0");
                    } else if (py::isString(result.get()) || py::isUnicode(result.get())) {
                        conditionMet = !py::asString(result.get()).empty();
                    } else if (py::isList(result.get())) {
                        conditionMet = py::listSize(result.get()) > 0;
                    } else if (py::isDict(result.get())) {
                        long long pos   = 0;
                        PyHandle  key   = nullptr;
                        PyHandle  value = nullptr;
                        conditionMet    = py::dictNext(result.get(), &pos, &key, &value);
                    } else {
                        conditionMet = true;
                    }
                } else {
                    py::clearError();
                    conditionMet = false;
                }
            } else {
                py::clearError();
                conditionMet = false;
            }
        }

        if (conditionMet) {
            shouldStop = true;
            stopReason = "breakpoint";
        }
    }

    if (mState == DebuggerState::Stepping) {
        int currentDepth = py::calculateFrameDepth(frame);

        switch (mStepMode) {
        case StepMode::Into:
            shouldStop = true;
            stopReason = "step";
            break;
        case StepMode::Over:
            if (currentDepth <= mStepDepth) {
                shouldStop = true;
                stopReason = "step";
            }
            break;
        case StepMode::Out:
            if (currentDepth < mStepDepth) {
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
    mState         = DebuggerState::Stopped;
    mCurrentFrame  = frame;
    mCurrentLine   = line;
    mCurrentSource = source;
    mStepMode      = StepMode::None;

    // 清除旧的变量引用
    clearVariableReferences();

    // 构建堆栈帧
    {
        std::lock_guard<std::mutex> lock(mFrameMutex);
        mStackFrames.clear();

        PyFrameHandle f   = frame;
        int           idx = 0;
        while (f && idx < dap::MaxStackFrames) {
            py::FrameInfo finfo = py::getFrameInfo(f);

            StackFrame sf;
            sf.id      = mNextFrameId++;
            sf.pyFrame = f;
            sf.line    = finfo.lineNumber;
            sf.column  = 1;
            sf.name    = finfo.funcName;
            // 将模块路径转换为文件系统路径，以便 VSCode 能正确打开源文件
            sf.source = path_utils::resolveToFilePath(finfo.filename);

            mStackFrames.push_back(sf);
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

    // 等待调试命令
    waitForCommand();
}

void DAPDebugger::onFrameExit(PyFrameHandle frame) {
    if (frame == mCachedFrame) {
        mCachedFrame = nullptr;
        mCachedFilename.clear();
    }
}


DAPDebugger& getDebugger() { return DAPDebugger::getInstance(); }
