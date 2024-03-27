#include "open62541pp/Server.h"

#include <atomic>
#include <cassert>
#include <cstddef>
#include <mutex>
#include <utility>  // move

#include "open62541pp/AccessControl.h"
#include "open62541pp/Client.h"
#include "open62541pp/Config.h"
#include "open62541pp/DataType.h"
#include "open62541pp/ErrorHandling.h"
#include "open62541pp/Event.h"
#include "open62541pp/Node.h"
#include "open62541pp/Session.h"
#include "open62541pp/TypeWrapper.h"
#include "open62541pp/ValueBackend.h"
#include "open62541pp/services/Attribute.h"
#include "open62541pp/types/Builtin.h"
#include "open62541pp/types/Composed.h"
#include "open62541pp/types/DataValue.h"
#include "open62541pp/types/Variant.h"

#include "CustomAccessControl.h"
#include "CustomDataTypes.h"
#include "CustomLogger.h"
#include "ServerContext.h"
#include "open62541_impl.h"

namespace opcua {

/* ------------------------------------------- Helper ------------------------------------------- */

inline static UA_ServerConfig* getConfig(UA_Server* server) noexcept {
    return UA_Server_getConfig(server);
}

inline static UA_ServerConfig* getConfig(Server* server) noexcept {
    return UA_Server_getConfig(server->handle());
}

/* ----------------------------------------- Connection ----------------------------------------- */

class Server::Connection {
public:
    explicit Connection(Server& server)
        : server_(UA_Server_new()),
          customAccessControl_(server),
          customDataTypes_(&getConfig(server_)->customDataTypes),
          customLogger_(getConfig(server_)->logger) {}

    ~Connection() {
        // don't use stop method here because it might throw an exception
        if (running_) {
            UA_Server_run_shutdown(handle());
        }
        UA_Server_delete(handle());
    }

    // prevent copy & move
    Connection(const Connection&) = delete;
    Connection(Connection&&) noexcept = delete;
    Connection& operator=(const Connection&) = delete;
    Connection& operator=(Connection&&) noexcept = delete;

    void runStartup() {
        if (!running_) {
            const auto status = UA_Server_run_startup(handle());
            throwIfBad(status);
        }
        running_ = true;
    }

    uint16_t runIterate() {
        if (!running_) {
            runStartup();
        }
        return UA_Server_run_iterate(handle(), false /* don't wait */);
    }

    void run() {
        if (running_) {
            return;
        }
        runStartup();
        // const std::lock_guard<std::mutex> lock(mutex_);
        while (running_) {
            // https://github.com/open62541/open62541/blob/master/examples/server_mainloop.c
            UA_Server_run_iterate(handle(), true /* wait for messages in the networklayer */);
        }
    }

    void stop() {
        running_ = false;
        // wait for run loop to complete
        // const std::lock_guard<std::mutex> lock(mutex_);
        const auto status = UA_Server_run_shutdown(handle());
        throwIfBad(status);
    }

    bool isRunning() const noexcept {
        return running_;
    }

    UA_Server* handle() noexcept {
        return server_;
    }

    ServerContext& getContext() noexcept {
        return context_;
    }

    auto& getCustomAccessControl() noexcept {
        return customAccessControl_;
    }

    const auto& getCustomAccessControl() const noexcept {
        return customAccessControl_;
    }

    auto& getCustomDataTypes() noexcept {
        return customDataTypes_;
    }

    auto& getCustomLogger() noexcept {
        return customLogger_;
    }

private:
    UA_Server* server_;
    ServerContext context_;
    CustomAccessControl customAccessControl_;
    CustomDataTypes customDataTypes_;
    CustomLogger customLogger_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;
};

/* ------------------------------------------- Server ------------------------------------------- */

static void applyDefaults(UA_ServerConfig* config) {
#ifdef UA_ENABLE_SUBSCRIPTIONS
    config->publishingIntervalLimits.min = 10;  // ms
    config->samplingIntervalLimits.min = 10;  // ms
#endif
#if UAPP_OPEN62541_VER_GE(1, 2)
    config->allowEmptyVariables = UA_RULEHANDLING_ACCEPT;  // allow empty variables
#endif
}

Server::Server(uint16_t port, ByteString certificate, Logger logger)
    : connection_(std::make_shared<Connection>(*this)) {
    // The logger should be set as soon as possible, ideally even before UA_ServerConfig_setMinimal.
    // However, the logger gets overwritten by UA_ServerConfig_setMinimal() in older versions of
    // open62541. The best we can do in this case, is to first call UA_ServerConfig_setMinimal and
    // then setLogger.
    auto setConfig = [&] {
        const auto status = UA_ServerConfig_setMinimal(
            getConfig(this), port, certificate.empty() ? nullptr : certificate.handle()
        );
        throwIfBad(status);
    };
#if UAPP_OPEN62541_VER_GE(1, 1)
    setLogger(std::move(logger));
    setConfig();
#else
    setConfig();
    setLogger(std::move(logger));
#endif
    applyDefaults(getConfig(this));
    setAccessControl(std::make_unique<AccessControlDefault>());
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
    : connection_(std::make_shared<Connection>(*this)) {
    const auto status = UA_ServerConfig_setDefaultWithSecurityPolicies(
        getConfig(this),
        port,
        certificate.handle(),
        privateKey.handle(),
        asNative(trustList.data()),
        trustList.size(),
        asNative(issuerList.data()),
        issuerList.size(),
        asNative(revocationList.data()),
        revocationList.size()
    );
    throwIfBad(status);
    applyDefaults(getConfig(this));
    setAccessControl(std::make_unique<AccessControlDefault>());
}
#endif

void Server::setLogger(Logger logger) {
    connection_->getCustomLogger().setLogger(std::move(logger));
}

// copy to endpoints needed, see: https://github.com/open62541/open62541/issues/1175
static void copyApplicationDescriptionToEndpoints(UA_ServerConfig* config) {
    for (size_t i = 0; i < config->endpointsSize; ++i) {
        auto& ref = asWrapper<ApplicationDescription>(config->endpoints[i].server);  // NOLINT
        ref = ApplicationDescription(config->applicationDescription);
    }
}

void Server::setCustomHostname(std::string_view hostname) {
    auto& ref = asWrapper<String>(getConfig(this)->customHostname);
    ref = String(hostname);
}

void Server::setApplicationName(std::string_view name) {
    auto& ref = asWrapper<LocalizedText>(getConfig(this)->applicationDescription.applicationName);
    ref = LocalizedText("", name);
    copyApplicationDescriptionToEndpoints(getConfig(this));
}

void Server::setApplicationUri(std::string_view uri) {
    auto& ref = asWrapper<String>(getConfig(this)->applicationDescription.applicationUri);
    ref = String(uri);
    copyApplicationDescriptionToEndpoints(getConfig(this));
}

void Server::setProductUri(std::string_view uri) {
    auto& ref = asWrapper<String>(getConfig(this)->applicationDescription.productUri);
    ref = String(uri);
    copyApplicationDescriptionToEndpoints(getConfig(this));
}

void Server::setServerName(std::string name __attribute_maybe_unused__) {
    // customhostname is signaled to discoveryserver
    getConfig(this)->customHostname = UA_String_fromChars(name.c_str());

#ifdef UA_ENABLE_DISCOVERY
    getConfig(this)->mdnsConfig.mdnsServerName = UA_String_fromChars(name.c_str());
#endif
}

void Server::registerOnDiscoveryServer(std::string url __attribute_maybe_unused__) {
#ifdef UA_ENABLE_DISCOVERY
    clientRegister_ = new Client();

    UA_UInt64 callbackId;
    throwIfBad(UA_Server_addPeriodicServerRegisterCallback(
        this->handle(), clientRegister_->handle(), url.c_str(), 10 * 60 * 1000, 500, &callbackId
    ));
#endif
}

void Server::unregisterFromDiscoveryServer(void) {
#ifdef UA_ENABLE_DISCOVERY
    throwIfBad(UA_Server_unregister_discovery(this->handle(), clientRegister_->handle()));

    delete clientRegister_;
#endif
}

void Server::setEnableDiscovery(bool enable_mDNS) {
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    /// Make sure servername is set
    if (UA_String_equal(&getConfig(this)->mdnsConfig.mdnsServerName, &UA_STRING_NULL)) {
        return;
    }

    // Enable the mDNS announce and response functionality
    getConfig(this)->mdnsEnabled = true;

    // Set applicationuri to reflect mDNS
    std::string applicationUri = std::string(
        asWrapper<String>(getConfig(this)->applicationDescription.applicationUri)
    );

    if (!enable_mDNS) {
        // See http://www.opcfoundation.org/UA/schemas/1.03/ServerCapabilities.csv
        // For a LDS server, you should only indicate the LDS capability.
        // If this instance is an LDS and at the same time a normal OPC UA server, you also have to
        // indicate the additional capabilities. NOTE: UaExpert does not show LDS-only servers in
        // the list. See also: https://forum.unified-automation.com/topic1987.html
        getConfig(this)->applicationDescription.applicationType =
            UA_APPLICATIONTYPE_DISCOVERYSERVER;

        applicationUri += ".lds";

        getConfig(this)->mdnsConfig.serverCapabilitiesSize = 1;
        UA_String* caps = (UA_String*)UA_Array_new(2, &UA_TYPES[UA_TYPES_STRING]);
        caps[0] = UA_String_fromChars("LDS");
        getConfig(this)->mdnsConfig.serverCapabilities = caps;
    } else {

        getConfig(this)->applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;

        applicationUri += ".multicast";

        getConfig(this)->mdnsConfig.serverCapabilitiesSize = 2;
        UA_String* caps = (UA_String*)UA_Array_new(2, &UA_TYPES[UA_TYPES_STRING]);
        caps[0] = UA_String_fromChars("LDS");
        caps[1] = UA_String_fromChars("NA");
        getConfig(this)->mdnsConfig.serverCapabilities = caps;
    }
    // set Names
    getConfig(this)->applicationDescription.applicationUri = UA_String_fromChars(
        applicationUri.c_str()
    );

    // set IP - listen on all interfaces
    getConfig(this)->mdnsInterfaceIP = UA_String_fromChars("0.0.0.0");
#endif
}

void Server::setOnServerRegisteredCallback(
    OnServerRegisteredCallback callback __attribute_maybe_unused__
) {
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    auto serverOnNetworkCallback =
        [](const UA_ServerOnNetwork* serverOnNetwork,
           UA_Boolean isServerAnnounce __attribute_maybe_unused__,
           UA_Boolean isTxtReceived __attribute_maybe_unused__,
           void* data) {
            char* discovery_url = NULL;
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

void Server::setAccessControl(AccessControlBase& accessControl) {
    connection_->getCustomAccessControl().setAccessControl(accessControl);
}

void Server::setAccessControl(std::unique_ptr<AccessControlBase> accessControl) {
    connection_->getCustomAccessControl().setAccessControl(std::move(accessControl));
}

std::vector<Session> Server::getSessions() const {
    return connection_->getCustomAccessControl().getSessions();
}

std::vector<std::string> Server::getNamespaceArray() {
    return services::readValue(*this, {0, UA_NS0ID_SERVER_NAMESPACEARRAY})
        .getArrayCopy<std::string>();
}

uint16_t Server::registerNamespace(std::string_view uri) {
    return UA_Server_addNamespace(handle(), std::string(uri).c_str());
}

void Server::setCustomDataTypes(std::vector<DataType> dataTypes) {
    connection_->getCustomDataTypes().setCustomDataTypes(std::move(dataTypes));
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
    auto& cb = static_cast<ServerContext::NodeContext*>(nodeContext)->valueCallback.onBeforeRead;
    if (cb) {
        detail::invokeCatchIgnore([&] { cb(asWrapper<DataValue>(*value)); });
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
    auto& cb = static_cast<ServerContext::NodeContext*>(nodeContext)->valueCallback.onAfterWrite;
    if (cb) {
        detail::invokeCatchIgnore([&] { cb(asWrapper<DataValue>(*value)); });
    }
}

void Server::setVariableNodeValueCallback(const NodeId& id, ValueCallback callback) {
    auto* nodeContext = getContext().getOrCreateNodeContext(id);
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
    auto& callback = static_cast<ServerContext::NodeContext*>(nodeContext)->dataSource.read;
    if (callback) {
        return detail::invokeCatchStatus([&] {
            callback(asWrapper<DataValue>(*value), asRange(range), includeSourceTimestamp);
        });
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
    auto& callback = static_cast<ServerContext::NodeContext*>(nodeContext)->dataSource.write;
    if (callback) {
        return detail::invokeCatchStatus([&] {
            callback(asWrapper<DataValue>(*value), asRange(range));
        });
    }
    return UA_STATUSCODE_BADINTERNALERROR;
}

void Server::setVariableNodeValueBackend(const NodeId& id, ValueBackendDataSource backend) {
    auto* nodeContext = getContext().getOrCreateNodeContext(id);
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
    return connection_->isRunning();
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
    return connection_->handle();
}

const UA_Server* Server::handle() const noexcept {
    return connection_->handle();
}

ServerContext& Server::getContext() noexcept {
    return connection_->getContext();
}

/* ---------------------------------------------------------------------------------------------- */

bool operator==(const Server& lhs, const Server& rhs) noexcept {
    return (lhs.handle() == rhs.handle());
}

bool operator!=(const Server& lhs, const Server& rhs) noexcept {
    return !(lhs == rhs);
}

}  // namespace opcua
