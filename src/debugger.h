#pragma once

#include "py_wrapper.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>

using json = nlohmann::json;

namespace dap {

constexpr int kDefaultPort         = 5678;
constexpr int kMaxStackFrames      = 50;
constexpr int kMaxVariables        = 100;
constexpr int kMaxValueLength      = 200;
constexpr int kMaxEvalResultLength = 500;
constexpr int kScopeMultiplier     = 1000;
constexpr int kVariableRefBase     = 10000;
constexpr int kLocalsScopeOffset   = 1;
constexpr int kGlobalsScopeOffset  = 2;

} // namespace dap

struct Breakpoint {
    int         id = 0;
    std::string source;
    int         line     = 0;
    bool        verified = false;
    std::string condition;

    json toJson() const {
        return {
            {      "id",       id},
            {"verified", verified},
            {    "line",     line}
        };
    }
};

struct StackFrame {
    int           id = 0;
    std::string   name;
    std::string   source;
    int           line    = 0;
    int           column  = 1;
    PyFrameHandle pyFrame = nullptr;

    json toJson() const {
        return {
            {    "id",                 id},
            {  "name",               name},
            {"source", {{"path", source}}},
            {  "line",               line},
            {"column",             column}
        };
    }
};

struct Variable {
    std::string name;
    std::string value;
    std::string type;
    int         variablesReference = 0;

    json toJson() const {
        return {
            {              "name",               name},
            {             "value",              value},
            {              "type",               type},
            {"variablesReference", variablesReference}
        };
    }
};


enum class DebuggerState { Disconnected, Initializing, Running, Stopped, Stepping, Terminated };

enum class StepMode { None, Over, Into, Out };

namespace PathUtils {

std::string normalize(const std::string& path);
bool        matches(const std::string& breakpointPath, const std::string& sourcePath);

void        registerPathMapping(const std::string& filePath);
std::string resolveToFilePath(const std::string& sourcePath);
void        clearPathMapping();

} // namespace PathUtils

class DAPMessageBuilder {
public:
    static json response(int requestSeq, const std::string& command, bool success, const json& body = nullptr);
    static json event(const std::string& eventName, const json& body = nullptr);
    static int  nextSeq();
};


class DAPDebugger {
public:
    static DAPDebugger& getInstance();

    bool initialize(int port = dap::kDefaultPort);
    void shutdown();

    void handleRequest(const std::string& request);

    int  setBreakpoint(const std::string& source, int line, const std::string& condition = "");
    void clearBreakpoints(const std::string& source);
    bool hasBreakpoint(const std::string& source, int line);
    bool hasBreakpoint(const std::string& source);
    bool hasBreakpointInCurrentFrame();

    // Python Hooks
    void onFrameEnter(PyFrameHandle frame);
    void onLineExecute(PyFrameHandle frame, int line);
    void onFrameExit(PyFrameHandle frame);

    DebuggerState getState() const { return state_; }

    bool isRunning() const {
        DebuggerState s = state_;
        return s == DebuggerState::Running || s == DebuggerState::Stepping;
    }

private:
    DAPDebugger();
    ~DAPDebugger();

    DAPDebugger(const DAPDebugger&)            = delete;
    DAPDebugger& operator=(const DAPDebugger&) = delete;

    // 网络
    void startServer(int port);
    void stopServer();
    void sendMessage(const json& message);
    void sendRaw(const std::string& message) const;

    // 协议处理器
    void processInitialize(int seq, const json& args);
    void processLaunch(int seq, const json& args);
    void processAttach(int seq, const json& args);
    void processSetBreakpoints(int seq, const json& args);
    void processConfigurationDone(int seq, const json& args);
    void processThreads(int seq, const json& args);
    void processStackTrace(int seq, const json& args);
    void processScopes(int seq, const json& args);
    void processVariables(int seq, const json& args);
    void processContinue(int seq, const json& args);
    void processNext(int seq, const json& args);
    void processStepIn(int seq, const json& args);
    void processStepOut(int seq, const json& args);
    void processPause(int seq, const json& args);
    void processEvaluate(int seq, const json& args);
    void processDisconnect(int seq, const json& args);

    // 变量处理
    int  registerVariableReference(PyHandle obj);
    json getVariablesFromDict(PyHandle dict);
    json getVariablesFromList(PyHandle list);
    json getVariablesFromTuple(PyHandle tuple);
    json getVariablesFromObject(PyHandle obj);
    json extractVariable(const std::string& name, PyHandle value);

    // 同步
    void waitForCommand();
    void notifyCommandReceived();

    // 状态
    std::atomic<DebuggerState> state_{DebuggerState::Disconnected};

    // 断点
    std::unordered_map<std::string, std::vector<Breakpoint>> breakpoints_;
    std::mutex                                               breakpointMutex_;
    int                                                      nextBreakpointId_ = 1;

    // 堆栈帧
    std::vector<StackFrame> stackFrames_;
    std::mutex              frameMutex_;
    int                     nextFrameId_ = 1;

    // 变量引用
    std::unordered_map<int, PyHandle> variableRefs_;
    int                               nextVarRef_ = 1;

    // 当前状态
    PyFrameHandle currentFrame_ = nullptr;
    int           currentLine_  = 0;
    std::string   currentSource_;

    PyFrameHandle cachedFrame_ = nullptr;
    std::string   cachedFilename_;

    // 单步状态
    StepMode      stepMode_       = StepMode::None;
    int           stepDepth_      = 0;
    PyFrameHandle stepStartFrame_ = nullptr;

    // 网络
    int               serverSocket_ = -1;
    int               clientSocket_ = -1;
    std::thread       serverThread_;
    std::atomic<bool> serverRunning_{false};

    // 命令同步
    std::mutex              commandMutex_;
    std::condition_variable commandCV_;
    std::atomic<bool>       commandReceived_{false};

    // 服务器启动同步
    std::mutex              serverStartMutex_;
    std::condition_variable serverStartCV_;
    std::atomic<bool>       serverStarted_{false};
};

DAPDebugger& getDebugger();
