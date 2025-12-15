#pragma once

#include "PyWrapper.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <functional>
#include <queue>
#include <future>

using json = nlohmann::json;

namespace dap {

constexpr int DefaultPort         = 5678;
constexpr int MaxStackFrames      = 50;
constexpr int MaxVariables        = 100;
constexpr int MaxValueLength      = 200;
constexpr int MaxEvalResultLength = 500;

} // namespace dap

enum class VariableRefType { Locals, Globals, Object };

struct VariableRef {
    VariableRefType type    = VariableRefType::Object;
    int             frameId = 0;
    PyHandle        object  = nullptr;
};

struct Breakpoint {
    int         id = 0;
    std::string source;
    int         line     = 0;
    bool        verified = false;
    std::string condition;
    std::string logMessage;

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

namespace path_utils {

std::string normalize(const std::string& path);
bool        matches(const std::string& breakpointPath, const std::string& sourcePath);

void        registerPathMapping(const std::string& filePath);
std::string resolveToFilePath(const std::string& sourcePath);
void        clearPathMapping();

} // namespace path_utils

class DAPMessageBuilder {
public:
    static json response(int requestSeq, const std::string& command, bool success, const json& body = nullptr);
    static json
    response(int requestSeq, const std::string& command, bool success, const json& body, const std::string& message);
    static json event(const std::string& eventName, const json& body = nullptr);
    static int  nextSeq();
};


class DAPDebugger {
public:
    static DAPDebugger& getInstance();

    bool initialize(int port = dap::DefaultPort);
    void shutdown();

    void handleRequest(const std::string& request);

    int setBreakpoint(
        const std::string& source,
        int                line,
        const std::string& condition  = "",
        const std::string& logMessage = ""
    );
    void        clearBreakpoints(const std::string& source);
    bool        hasBreakpoint(const std::string& source, int line);
    bool        hasBreakpoint(const std::string& source);
    bool        hasBreakpointInCurrentFrame();
    Breakpoint* getBreakpoint(const std::string& source, int line);
    std::string formatLogMessage(const std::string& message, PyHandle globals, PyHandle locals);

    // Python Hooks
    void onFrameEnter(PyFrameHandle frame);
    void onLineExecute(PyFrameHandle frame, int line);
    void onFrameExit(PyFrameHandle frame);

    DebuggerState getState() const { return mState; }

    bool isRunning() const {
        DebuggerState s = mState;
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
    void processSetExceptionBreakpoints(int seq, const json& args);
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
    void processSetVariable(int seq, const json& args);
    void processCompletions(int seq, const json& args);
    void processDisconnect(int seq, const json& args);

    // 变量处理
    int  registerVariableReference(PyHandle obj);
    void clearVariableReferences();
    json getVariablesFromDict(PyHandle dict);
    json getVariablesFromList(PyHandle list);
    json getVariablesFromTuple(PyHandle tuple);
    json getVariablesFromSet(PyHandle set);
    json getVariablesFromObject(PyHandle obj);
    json extractVariable(const std::string& name, PyHandle value);

    // 同步
    void waitForCommand();
    void notifyCommandReceived();

    // 主线程执行循环（在断点处调用）
    void debuggerLoop();

    // 提交任务到主线程执行
    template <typename F>
    auto submitToMainThread(F&& func) -> decltype(func());

    // 状态
    std::atomic<DebuggerState> mState{DebuggerState::Disconnected};

    // 断点
    std::unordered_map<std::string, std::vector<Breakpoint>> mBreakpoints;
    std::mutex                                               mBreakpointMutex;
    int                                                      mNextBreakpointId = 1;

    // 堆栈帧
    std::vector<StackFrame> mStackFrames;
    std::mutex              mFrameMutex;
    int                     mNextFrameId = 1;

    // 变量引用
    std::unordered_map<int, VariableRef> mVariableRefs;
    int                                  mNextVarRef = 1;

    // 当前状态
    PyFrameHandle mCurrentFrame = nullptr;
    int           mCurrentLine  = 0;
    std::string   mCurrentSource;

    PyFrameHandle mCachedFrame = nullptr;
    std::string   mCachedFilename;

    // 单步状态
    StepMode      mStepMode       = StepMode::None;
    int           mStepDepth      = 0;
    PyFrameHandle mStepStartFrame = nullptr;

    // 网络
    int               mServerSocket = -1;
    int               mClientSocket = -1;
    std::thread       mServerThread;
    std::atomic<bool> mServerRunning{false};

    // 命令同步
    std::mutex              mCommandMutex;
    std::condition_variable mCommandCv;
    std::atomic<bool>       mCommandReceived{false};

    // 主线程任务队列
    struct PendingTask {
        std::function<void()>               task;
        std::shared_ptr<std::promise<void>> completion;
    };
    std::queue<PendingTask> mTaskQueue;
    std::mutex              mTaskQueueMutex;
    std::condition_variable mTaskQueueCv;
    std::atomic<bool>       mShouldContinue{false};

    // 服务器启动同步
    std::mutex              mServerStartMutex;
    std::condition_variable mServerStartCv;
    std::atomic<bool>       mServerStarted{false};
};

DAPDebugger& getDebugger();
