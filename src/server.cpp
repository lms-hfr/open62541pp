#include "open62541pp/server.hpp"

#include <atomic>
#include <cassert>
#include <mutex>
#include <utility>  // move

#include "open62541pp/datatype.hpp"
#include "open62541pp/detail/connection.hpp"
#include "open62541pp/detail/result_utils.hpp"  // tryInvoke
#include "open62541pp/detail/server_context.hpp"
#include "open62541pp/event.hpp"
#include "open62541pp/exception.hpp"
#include "open62541pp/node.hpp"
#include "open62541pp/plugin/accesscontrol.hpp"
#include "open62541pp/plugin/nodestore.hpp"
#include "open62541pp/services/attribute_highlevel.hpp"
#include "open62541pp/session.hpp"
#include "open62541pp/types.hpp"
#include "open62541pp/types_composed.hpp"
#include "open62541pp/wrapper.hpp"  // asWrapper

#include "server_config.hpp"

namespace opcua {

/* --------------------------------------- ConnectionBase -------------------------------------- */

namespace detail {

[[nodiscard]] static UA_Server* allocateServer() {
    auto* server = UA_Server_new();
    if (server == nullptr) {
        throw BadStatus(UA_STATUSCODE_BADOUTOFMEMORY);
    }
    return server;
}

static UA_StatusCode activateSession(
    UA_Server* server,
    UA_AccessControl* ac,
    const UA_EndpointDescription* endpointDescription,
    const UA_ByteString* secureChannelRemoteCertificate,
    const UA_NodeId* sessionId,
    const UA_ExtensionObject* userIdentityToken,
    void** sessionContext
) {
    auto* context = getContext(server);
    if (context == nullptr || context->sessionRegistry.activateSessionUser == nullptr) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    // call user-defined function
    auto status = context->sessionRegistry.activateSessionUser(
        server,
        ac,
        endpointDescription,
        secureChannelRemoteCertificate,
        sessionId,
        userIdentityToken,
        sessionContext
    );
    if (isGood(status) && sessionId != nullptr) {
        context->sessionRegistry.sessionIds.insert(asWrapper<NodeId>(*sessionId));
    }
    return status;
}

static void closeSession(
    UA_Server* server, UA_AccessControl* ac, const UA_NodeId* sessionId, void* sessionContext
) {
    auto* context = getContext(server);
    if (context == nullptr || context->sessionRegistry.closeSessionUser == nullptr) {
        return;
    }
    // call user-defined function
    context->sessionRegistry.closeSessionUser(server, ac, sessionId, sessionContext);
    if (sessionId != nullptr) {
        context->sessionRegistry.sessionIds.erase(asWrapper<NodeId>(*sessionId));
    }
}

struct ServerConnection : public ConnectionBase<Server> {
    explicit ServerConnection()
        : server(allocateServer()),
          config(*detail::getConfig(server)) {}

    ~ServerConnection() {
        // don't use stop method here because it might throw an exception
        if (running) {
            UA_Server_run_shutdown(server);
        }
        UA_Server_delete(server);
    }

    ServerConnection(const ServerConnection&) = delete;
    ServerConnection(ServerConnection&&) noexcept = delete;
    ServerConnection& operator=(const ServerConnection&) = delete;
    ServerConnection& operator=(ServerConnection&&) noexcept = delete;

    void applySessionRegistry() {
#if UAPP_OPEN62541_VER_GE(1, 3)
        // Make sure to call this function only once after access control is initialized or changed.
        // The function pointers to activateSession / closeSession might not be unique and the
        // the pointer comparison might fail resulting in stack overflows:
        // - https://github.com/open62541pp/open62541pp/issues/285
        // - https://stackoverflow.com/questions/31209693/static-library-linked-two-times
        if (config->accessControl.activateSession != &activateSession) {
            context.sessionRegistry.activateSessionUser = config->accessControl.activateSession;
            config->accessControl.activateSession = &activateSession;
        }
        if (config->accessControl.closeSession != &closeSession) {
            context.sessionRegistry.closeSessionUser = config->accessControl.closeSession;
            config->accessControl.closeSession = &closeSession;
        }
#endif
    }

    void applyDefaults() {
#ifdef UA_ENABLE_SUBSCRIPTIONS
        config->publishingIntervalLimits.min = 10;  // ms
        config->samplingIntervalLimits.min = 10;  // ms
#endif
#if UAPP_OPEN62541_VER_GE(1, 2)
        config->allowEmptyVariables = UA_RULEHANDLING_ACCEPT;  // allow empty variables
#endif
#if UAPP_OPEN62541_VER_GE(1, 3)
        config->context = this;
#endif
    }

    void runStartup() {
        applyDefaults();
        throwIfBad(UA_Server_run_startup(server));
        running = true;
    }

    uint16_t runIterate() {
        if (!running) {
            runStartup();
        }
        auto interval = UA_Server_run_iterate(server, false /* don't wait */);
        context.exceptionCatcher.rethrow();
        return interval;
    }

    void run() {
        if (running) {
            return;
        }
        runStartup();
        const std::lock_guard lock(mutexRun);
        try {
            while (running) {
                // https://github.com/open62541/open62541/blob/master/examples/server_mainloop.c
                UA_Server_run_iterate(server, true /* wait for messages in the networklayer */);
                context.exceptionCatcher.rethrow();
            }
        } catch (...) {
            running = false;
            throw;
        }
    }

    void stop() {
        running = false;
        // wait for run loop to complete
        const std::lock_guard<std::mutex> lock(mutexRun);
        throwIfBad(UA_Server_run_shutdown(server));
    }

    UA_Server* server;
    ServerConfig config;
    detail::ServerContext context;
    std::atomic<bool> running{false};
    std::mutex mutexRun;
};

}  // namespace detail

/* ------------------------------------------- Server ------------------------------------------- */

Server::Server(uint16_t port, ByteString certificate, LogFunction logger)
    : connection_(std::make_unique<detail::ServerConnection>()) {
    // The logger should be set as soon as possible, ideally even before UA_ServerConfig_setMinimal.
    // However, the logger gets overwritten by UA_ServerConfig_setMinimal() in older versions of
    // open62541. The best we can do in this case, is to first call UA_ServerConfig_setMinimal and
    // then setLogger.
    auto setConfig = [&] {
        throwIfBad(UA_ServerConfig_setMinimal(
            detail::getConfig(handle()), port, certificate.empty() ? nullptr : certificate.handle()
        ));
    };
#if UAPP_OPEN62541_VER_GE(1, 1)
    setLogger(std::move(logger));
    setConfig();
#else
    setConfig();
    setLogger(std::move(logger));
#endif
    connection_->applySessionRegistry();
    connection_->applyDefaults();
}

#ifdef UA_ENABLE_ENCRYPTION
Server::Server(
    uint16_t port,
    const ByteString& certificate,
    const ByteString& privateKey,
    Span<const ByteString> trustList,
    Span<const ByteString> issuerList,
    Span<const ByteString> revocationList
)
    : connection_(std::make_unique<detail::ServerConnection>()) {
    throwIfBad(UA_ServerConfig_setDefaultWithSecurityPolicies(
        detail::getConfig(handle()),
        port,
        certificate.handle(),
        privateKey.handle(),
        asNative(trustList.data()),
        trustList.size(),
        asNative(issuerList.data()),
        issuerList.size(),
        asNative(revocationList.data()),
        revocationList.size()
    ));
    connection_->applySessionRegistry();
    connection_->applyDefaults();
}
#endif

Server::~Server() = default;

void Server::setLogger(LogFunction logger) {
    connection_->config.setLogger(std::move(logger));
}

inline static ApplicationDescription& getApplicationDescription(Server& server) noexcept {
    return asWrapper<ApplicationDescription>(detail::getConfig(server).applicationDescription);
}

// copy to endpoints needed, see: https://github.com/open62541/open62541/issues/1175
inline static void copyApplicationDescriptionToEndpoints(Server& server) {
    auto endpoints = Span(
        asWrapper<EndpointDescription>(detail::getConfig(server).endpoints),
        detail::getConfig(server).endpointsSize
    );
    for (auto& endpoint : endpoints) {
        endpoint.getServer() = getApplicationDescription(server);
    }
}

void Server::setCustomHostname([[maybe_unused]] std::string_view hostname) {
#if UAPP_OPEN62541_VER_LE(1, 3)
    asWrapper<String>(detail::getConfig(*this).customHostname) = String(hostname);
#endif
}

void Server::setApplicationName(std::string_view name) {
    getApplicationDescription(*this).getApplicationName() = LocalizedText("", name);
    copyApplicationDescriptionToEndpoints(*this);
}

void Server::setApplicationUri(std::string_view uri) {
    getApplicationDescription(*this).getApplicationUri() = String(uri);
    copyApplicationDescriptionToEndpoints(*this);
}

void Server::setProductUri(std::string_view uri) {
    getApplicationDescription(*this).getProductUri() = String(uri);
    copyApplicationDescriptionToEndpoints(*this);
}
////////////
void Server::setServerName(std::string name __attribute_maybe_unused__) {
#ifdef UA_ENABLE_DISCOVERY
    detail::getConfig(*this).mdnsConfig.mdnsServerName = UA_String_fromChars(name.c_str());
#endif
}

void Server::registerOnDiscoveryServer(std::string url __attribute_maybe_unused__)
{
#ifdef UA_ENABLE_DISCOVERY
    UA_ClientConfig cc;
    memset(&cc, 0, sizeof(UA_ClientConfig));
    UA_ClientConfig_setDefault(&cc);
    UA_StatusCode retval = UA_Server_registerDiscovery(this->handle(), &cc, UA_String_fromChars(url.c_str()), UA_STRING_NULL);

    if (retval != UA_STATUSCODE_GOOD)
    {
      //  UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
      //               "Could not create periodic job for server register. StatusCode %s",
      //               UA_StatusCode_name(retval));
    }

    /*
    clientRegister_ = new Client();
    UA_UInt64 callbackId;
    throwIfBad(UA_Server_addPeriodicServerRegisterCallback(
    this->handle(), clientRegister_->handle(), url.c_str(), 10 * 60 * 1000, 500, &callbackId
    )); */
#endif
}

void Server::unregisterFromDiscoveryServer(std::string url __attribute_maybe_unused__)
{
#ifdef UA_ENABLE_DISCOVERY
    //  throwIfBad(UA_Server_unregister_discovery(this->handle(), clientRegister_->handle()));
    //  delete clientRegister_;
    UA_ClientConfig cc;
    memset(&cc, 0, sizeof(UA_ClientConfig));
    UA_ClientConfig_setDefault(&cc);
    UA_StatusCode retval = UA_Server_deregisterDiscovery(this->handle(), &cc, UA_String_fromChars(url.c_str()));
    if (retval != UA_STATUSCODE_GOOD)
    {
      //  UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
      //               "Could not create periodic job for server register. StatusCode %s",
      //               UA_StatusCode_name(retval));
    }
#endif
}

void Server::setEnableDiscovery()
{
#ifdef UA_ENABLE_DISCOVERY
    /// Make sure servername is set
    if (UA_String_equal(&detail::getConfig(*this).mdnsConfig.mdnsServerName, &UA_STRING_NULL))
    {
        return;
    }
    detail::getConfig(*this).applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;
    // Enable the mDNS announce and response functionality
    detail::getConfig(*this).mdnsEnabled = true;
    // Set applicationuri to reflect mDNS
    std::string applicationUri = std::string(
        asWrapper<String>(detail::getConfig(*this).applicationDescription.applicationUri));

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    applicationUri += ".multicast";
    detail::getConfig(*this).mdnsConfig.serverCapabilitiesSize = 2;
    UA_String* caps = (UA_String*)UA_Array_new(2, &UA_TYPES[UA_TYPES_STRING]);
    caps[0] = UA_String_fromChars("LDS");
    caps[1] = UA_String_fromChars("NA");
    detail::getConfig(*this).mdnsConfig.serverCapabilities = caps;
#else
    applicationUri += ".lds";
    // See http://www.opcfoundation.org/UA/schemas/1.03/ServerCapabilities.csv
    // For a LDS server, you should only indicate the LDS capability.
    // If this instance is an LDS and at the same time a normal OPC UA server, you also have to
    // indicate the additional capabilities. NOTE: UaExpert does not show LDS-only servers in the
    // list. See also: https://forum.unified-automation.com/topic1987.html
    detail::getConfig(*this).mdnsConfig.serverCapabilitiesSize = 1;
    UA_String* caps = (UA_String*)UA_Array_new(2, &UA_TYPES[UA_TYPES_STRING]);
    caps[0] = UA_String_fromChars("LDS");
    detail::getConfig(*this).mdnsConfig.serverCapabilities = caps;
#endif
    // set Names
    detail::getConfig(*this).applicationDescription.applicationUri = UA_String_fromChars(
        applicationUri.c_str());
    // set IP
    detail::getConfig(*this).mdnsInterfaceIP = UA_String_fromChars("127.0.0.1");
#endif
}

void Server::setOnServerRegisteredCallback(OnServerRegisteredCallback callback __attribute_maybe_unused__) {
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    auto serverOnNetworkCallback =
        [](const UA_ServerOnNetwork* serverOnNetwork,
           UA_Boolean isServerAnnounce,
           UA_Boolean isTxtReceived,
           void* data) {
            static char* discovery_url = NULL;
            if (discovery_url != NULL || !isServerAnnounce) {
                return;  // we already have everything we need or we only want server announces
            }
            if (!isTxtReceived) {
                return;  // we wait until the corresponding TXT record is announced.
                         // Problem: how to handle if a Server does not announce the
                         // optional TXT?
            }
            // here you can filter for a specific LDS server, e.g. call FindServers on
            // the serverOnNetwork to make sure you are registering with the correct
            // LDS. We will ignore this for now
            if (discovery_url != NULL) {
                UA_free(discovery_url);
            }
            discovery_url = (char*)UA_malloc(serverOnNetwork->discoveryUrl.length + 1);
            memcpy(
                discovery_url,
                serverOnNetwork->discoveryUrl.data,
                serverOnNetwork->discoveryUrl.length
            );
            discovery_url[serverOnNetwork->discoveryUrl.length] = 0;
            // signal to upper layers
            ((OnServerRegisteredCallback)data)(discovery_url);
        };
    // call services
    UA_Server_setServerOnNetworkCallback(this->handle(), serverOnNetworkCallback, (void*)callback);
#endif
}

///////////////////////////////////////////
void Server::setAccessControl(AccessControlBase& accessControl) {
    connection_->config.setAccessControl(accessControl);
    connection_->applySessionRegistry();
}

void Server::setAccessControl(std::unique_ptr<AccessControlBase> accessControl) {
    connection_->config.setAccessControl(std::move(accessControl));
    connection_->applySessionRegistry();
}

std::vector<Session> Server::getSessions() {
    std::vector<Session> sessions;
    for (auto&& id : connection_->context.sessionRegistry.sessionIds) {
        sessions.emplace_back(*this, id);
    }
    return sessions;
}

std::vector<std::string> Server::getNamespaceArray() {
    return services::readValue(*this, {0, UA_NS0ID_SERVER_NAMESPACEARRAY})
        .value()
        .getArrayCopy<std::string>();
}

NamespaceIndex Server::registerNamespace(std::string_view uri) {
    return UA_Server_addNamespace(handle(), std::string(uri).c_str());
}

void Server::setCustomDataTypes(std::vector<DataType> dataTypes) {
    connection_->config.setCustomDataTypes(std::move(dataTypes));
}

static void valueCallbackOnRead(
    [[maybe_unused]] UA_Server* server,
    [[maybe_unused]] const UA_NodeId* sessionId,
    [[maybe_unused]] void* sessionContext,
    [[maybe_unused]] const UA_NodeId* nodeId,
    void* nodeContext,
    [[maybe_unused]] const UA_NumericRange* range,
    const UA_DataValue* value
) noexcept {
    assert(nodeContext != nullptr && value != nullptr);
    auto& cb = static_cast<detail::NodeContext*>(nodeContext)->valueCallback.onBeforeRead;
    if (cb) {
        detail::tryInvoke([&] { cb(asWrapper<DataValue>(*value)); });
    }
}

static void valueCallbackOnWrite(
    [[maybe_unused]] UA_Server* server,
    [[maybe_unused]] const UA_NodeId* sessionId,
    [[maybe_unused]] void* sessionContext,
    [[maybe_unused]] const UA_NodeId* nodeId,
    void* nodeContext,
    [[maybe_unused]] const UA_NumericRange* range,
    const UA_DataValue* value
) noexcept {
    assert(nodeContext != nullptr && value != nullptr);
    auto& cb = static_cast<detail::NodeContext*>(nodeContext)->valueCallback.onAfterWrite;
    if (cb) {
        detail::tryInvoke([&] { cb(asWrapper<DataValue>(*value)); });
    }
}

void Server::setVariableNodeValueCallback(const NodeId& id, ValueCallback callback) {
    auto* nodeContext = detail::getContext(*this).nodeContexts[id];
    nodeContext->valueCallback = std::move(callback);
    throwIfBad(UA_Server_setNodeContext(handle(), id, nodeContext));

    UA_ValueCallback callbackNative;
    callbackNative.onRead = valueCallbackOnRead;
    callbackNative.onWrite = valueCallbackOnWrite;
    throwIfBad(UA_Server_setVariableNode_valueCallback(handle(), id, callbackNative));
}

inline static NumericRange asRange(const UA_NumericRange* range) noexcept {
    return range == nullptr ? NumericRange() : NumericRange(*range);
}

static UA_StatusCode valueSourceRead(
    [[maybe_unused]] UA_Server* server,
    [[maybe_unused]] const UA_NodeId* sessionId,
    [[maybe_unused]] void* sessionContext,
    [[maybe_unused]] const UA_NodeId* nodeId,
    void* nodeContext,
    UA_Boolean includeSourceTimestamp,
    const UA_NumericRange* range,
    UA_DataValue* value
) noexcept {
    assert(nodeContext != nullptr && value != nullptr);
    auto& callback = static_cast<detail::NodeContext*>(nodeContext)->dataSource.read;
    if (callback) {
        auto result = detail::tryInvoke(
            callback, asWrapper<DataValue>(*value), asRange(range), includeSourceTimestamp
        );
        return result.code();
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}

static UA_StatusCode valueSourceWrite(
    [[maybe_unused]] UA_Server* server,
    [[maybe_unused]] const UA_NodeId* sessionId,
    [[maybe_unused]] void* sessionContext,
    [[maybe_unused]] const UA_NodeId* nodeId,
    void* nodeContext,
    const UA_NumericRange* range,
    const UA_DataValue* value
) noexcept {
    assert(nodeContext != nullptr && value != nullptr);
    auto& callback = static_cast<detail::NodeContext*>(nodeContext)->dataSource.write;
    if (callback) {
        auto result = detail::tryInvoke(callback, asWrapper<DataValue>(*value), asRange(range));
        return result.code();
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}

void Server::setVariableNodeValueBackend(const NodeId& id, ValueBackendDataSource backend) {
    auto* nodeContext = detail::getContext(*this).nodeContexts[id];
    nodeContext->dataSource = std::move(backend);
    throwIfBad(UA_Server_setNodeContext(handle(), id, nodeContext));

    UA_DataSource dataSourceNative;
    dataSourceNative.read = valueSourceRead;
    dataSourceNative.write = valueSourceWrite;
    throwIfBad(UA_Server_setVariableNode_dataSource(handle(), id, dataSourceNative));
}

#ifdef UA_ENABLE_SUBSCRIPTIONS
Subscription<Server> Server::createSubscription() noexcept {
    return {*this, 0U};
}
#endif

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
Event Server::createEvent(const NodeId& eventType) {
    return Event(*this, eventType);
}
#endif

uint16_t Server::runIterate() {
    return connection_->runIterate();
}

void Server::run() {
    connection_->run();
}

void Server::stop() {
    connection_->stop();
}

bool Server::isRunning() const noexcept {
    return connection_->running;
}

Node<Server> Server::getNode(NodeId id) {
    return {*this, std::move(id)};
}

Node<Server> Server::getRootNode() {
    return {*this, {0, UA_NS0ID_ROOTFOLDER}};
}

Node<Server> Server::getObjectsNode() {
    return {*this, {0, UA_NS0ID_OBJECTSFOLDER}};
}

Node<Server> Server::getTypesNode() {
    return {*this, {0, UA_NS0ID_TYPESFOLDER}};
}

Node<Server> Server::getViewsNode() {
    return {*this, {0, UA_NS0ID_VIEWSFOLDER}};
}

UA_Server* Server::handle() noexcept {
    return connection_->server;
}

const UA_Server* Server::handle() const noexcept {
    return connection_->server;
}

/* -------------------------------------- Helper functions -------------------------------------- */

namespace detail {

UA_ServerConfig* getConfig(UA_Server* server) noexcept {
    return UA_Server_getConfig(server);
}

UA_ServerConfig& getConfig(Server& server) noexcept {
    return *getConfig(server.handle());
}

UA_Logger* getLogger(UA_Server* server) noexcept {
    auto* config = detail::getConfig(server);
    if (config == nullptr) {
        return nullptr;
    }
#if UAPP_OPEN62541_VER_GE(1, 4)
    return config->logging;
#else
    return &config->logger;
#endif
}

UA_Logger* getLogger(Server& server) noexcept {
    return getLogger(server.handle());
}

ServerConnection* getConnection([[maybe_unused]] UA_Server* server) noexcept {
#if UAPP_OPEN62541_VER_GE(1, 3)
    auto* config = getConfig(server);
    if (config == nullptr) {
        return nullptr;
    }
    // UA_ServerConfig.context pointer available since open62541 v1.3
    auto* state = static_cast<detail::ServerConnection*>(config->context);
    assert(state != nullptr);
    assert(state->server == server);
    return state;
#else
    return nullptr;
#endif
}

ServerConnection& getConnection(Server& server) noexcept {
    auto* state = server.connection_.get();
    assert(state != nullptr);
    return *state;
}

Server* getWrapper(UA_Server* server) noexcept {
    auto* state = getConnection(server);
    if (state == nullptr) {
        return nullptr;
    }
    return state->wrapperPtr();
}

ServerContext* getContext(UA_Server* server) noexcept {
    auto* state = getConnection(server);
    if (state == nullptr) {
        return nullptr;
    }
    return &state->context;
}

ServerContext& getContext(Server& server) noexcept {
    return getConnection(server).context;
}

}  // namespace detail

}  // namespace opcua
