#pragma once

#include <cstdint>
#include <functional>
#include <type_traits>
#include <vector>

#include "open62541pp/Config.h"
#include "open62541pp/MonitoredItem.h"
#include "open62541pp/services/MonitoredItem.h"
#include "open62541pp/services/Subscription.h"
#include "open62541pp/types/NodeId.h"

#ifdef UA_ENABLE_SUBSCRIPTIONS

namespace opcua {

// forward declarations
class Client;
class DataValue;
class EventFilter;
class Server;
template <typename T>
class Span;
class Variant;

using SubscriptionParameters = services::SubscriptionParameters;
using MonitoringParametersEx = services::MonitoringParametersEx;

/// Data change notification callback.
/// @tparam T Server or Client
template <typename T>
using DataChangeCallback =
    std::function<void(const MonitoredItem<T>& item, const DataValue& value)>;

/// Event notification callback.
/// @tparam T Server or Client
template <typename T>
using EventCallback =
    std::function<void(const MonitoredItem<T>& item, Span<const Variant> eventFields)>;

/**
 * High-level subscription class.
 *
 * The API is symmetric for both Server and Client, although servers don't use the subscription
 * mechanism of OPC UA to transport notifications of data changes and events. Instead MonitoredItems
 * are registered locally. Notifications are then forwarded to user-defined callbacks instead of a
 * remote client. The `subscriptionId` for servers is always `0U`.
 *
 * @note Not all methods are available and implemented for servers.
 *
 * Use the free functions in the `services` namespace for more advanced usage:
 * - @ref Subscription
 * - @ref MonitoredItem
 */
template <typename Connection>
class Subscription {
public:
    /// Wrap an existing subscription.
    /// The `subscriptionId` is ignored and set to `0U` for servers.
    Subscription(Connection& connection, uint32_t subscriptionId) noexcept
        : connection_(connection),
          subscriptionId_(std::is_same_v<Connection, Server> ? 0U : subscriptionId) {}

    /// Get the server/client instance.
    Connection& getConnection() noexcept {
        return connection_;
    }

    /// Get the server/client instance.
    const Connection& getConnection() const noexcept {
        return connection_;
    }

    /// Get the server-assigned identifier of this subscription.
    uint32_t getSubscriptionId() const noexcept {
        return subscriptionId_;
    }

    /// Get all local monitored items.
    std::vector<MonitoredItem<Connection>> getMonitoredItems();

    /// Modify this subscription.
    /// @note Not implemented for Server.
    /// @see services::modifySubscription
    void setSubscriptionParameters(SubscriptionParameters& parameters);

    /// Enable/disable publishing of notification messages.
    /// @note Not implemented for Server.
    /// @see services::setPublishingMode
    void setPublishingMode(bool publishing);

    /// Create a monitored item for data change notifications (default settings).
    /// The monitoring mode is set to MonitoringMode::Reporting and the default open62541
    /// MonitoringParametersEx are used.
    /// @see services::MonitoringParametersEx
    MonitoredItem<Connection> subscribeDataChange(
        const NodeId& id, AttributeId attribute, DataChangeCallback<Connection> onDataChange
    );

    /// Create a monitored item for data change notifications.
    /// @copydetails services::MonitoringParametersEx
    MonitoredItem<Connection> subscribeDataChange(
        const NodeId& id,
        AttributeId attribute,
        MonitoringMode monitoringMode,
        MonitoringParametersEx& parameters,
        DataChangeCallback<Connection> onDataChange
    );

    /// Create a monitored item for event notifications (default settings).
    /// The monitoring mode is set to MonitoringMode::Reporting and the default open62541
    /// MonitoringParametersEx are used.
    /// @note Not implemented for Server.
    MonitoredItem<Connection> subscribeEvent(
        const NodeId& id, const EventFilter& eventFilter, EventCallback<Connection> onEvent
    );

    /// Create a monitored item for event notifications.
    /// @copydetails services::MonitoringParametersEx
    /// @note Not implemented for Server.
    MonitoredItem<Connection> subscribeEvent(
        const NodeId& id,
        MonitoringMode monitoringMode,
        MonitoringParametersEx& parameters,
        EventCallback<Connection> onEvent
    );

    /// Delete this subscription.
    /// @note Not implemented for Server.
    /// @see services::deleteSubscription
    void deleteSubscription();

private:
    Connection& connection_;
    uint32_t subscriptionId_{0U};
};

/* ---------------------------------------------------------------------------------------------- */

template <typename T>
inline bool operator==(const Subscription<T>& lhs, const Subscription<T>& rhs) noexcept {
    return (lhs.getConnection() == rhs.getConnection()) &&
           (lhs.getSubscriptionId() == rhs.getSubscriptionId());
}

template <typename T>
inline bool operator!=(const Subscription<T>& lhs, const Subscription<T>& rhs) noexcept {
    return !(lhs == rhs);
}

}  // namespace opcua

#endif
