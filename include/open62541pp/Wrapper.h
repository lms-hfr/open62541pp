#pragma once

#include <type_traits>

namespace opcua {

/**
 * @defgroup Wrapper Wrapper classes
 *
 * All wrapper classes inherit from Wrapper (and optionally from TypeWrapper).
 * Native open62541 objects can be accessed using the Wrapper::handle() method.
 *
 * Wrapper types are pointer-interconvertible to the wrapped native type and vice versa:
 * - Use asWrapper(NativeType*) to cast native object pointers to wrapper object pointers.
 * - Use asWrapper(NativeType&) to cast native object references to wrapper object references.
 * - Use asNative(WrapperType*) to cast wrapper object pointers to native object pointers.
 * - Use asNative(WrapperType&) to cast wrapper object references to native object references.
 *
 * According to the standard:
 * > One is a standard-layout class object (wrapper) and the other is the first non-static data
 * > member of that object (wrapped native type)
 * Derived classes must fulfill the requirements of standard-layout types to be convertible.
 * @see https://en.cppreference.com/w/cpp/language/static_cast#pointer-interconvertible
 */

/**
 * Template base class to wrap native objects.
 * @ingroup Wrapper
 */
template <typename T>
class Wrapper {
public:
    using NativeType = T;

    constexpr Wrapper() = default;

    constexpr explicit Wrapper(const T& native)
        : native_(native) {}

    constexpr explicit Wrapper(T&& native) noexcept
        : native_(std::move(native)) {}

    /// Implicit conversion to native object.
    constexpr operator T&() noexcept {  // NOLINT
        return native_;
    }

    /// Implicit conversion to native object.
    constexpr operator const T&() const noexcept {  // NOLINT
        return native_;
    }

    /// Member access to native object.
    constexpr T* operator->() noexcept {
        return &native_;
    }

    /// Member access to native object.
    constexpr const T* operator->() const noexcept {
        return &native_;
    }

    /// Return pointer to native object.
    constexpr T* handle() noexcept {
        return &native_;
    }

    /// Return pointer to native object.
    constexpr const T* handle() const noexcept {
        return &native_;
    }

protected:
    constexpr const T& native() const noexcept {
        return native_;
    }

    constexpr T& native() noexcept {
        return native_;
    }

private:
    T native_{};
};

/* -------------------------------------------- Trait ------------------------------------------- */

namespace detail {

template <typename T>
struct IsWrapper {
    // https://stackoverflow.com/a/51910887
    template <typename U>
    static std::true_type check(const Wrapper<U>&);
    static std::false_type check(...);

    using type = decltype(check(std::declval<T&>()));  // NOLINT
    static constexpr bool value = type::value;
};

template <typename T>
inline constexpr bool isWrapper = IsWrapper<T>::value;

}  // namespace detail

/* ------------------------------ Cast native type to wrapper type ------------------------------ */

namespace detail {

template <typename WrapperType>
struct WrapperConversion {
    static_assert(isWrapper<WrapperType>);
    static_assert(std::is_standard_layout_v<WrapperType>);

    using NativeType = typename WrapperType::NativeType;

    static constexpr WrapperType* asWrapper(NativeType* native) noexcept {
        return static_cast<WrapperType*>(static_cast<void*>(native));
    }

    static constexpr const WrapperType* asWrapper(const NativeType* native) noexcept {
        return static_cast<const WrapperType*>(static_cast<const void*>(native));
    }

    static constexpr WrapperType& asWrapper(NativeType& native) noexcept {
        return *asWrapper(&native);
    }

    static constexpr const WrapperType& asWrapper(const NativeType& native) noexcept {
        return *asWrapper(&native);
    }

    static constexpr NativeType* asNative(WrapperType* wrapper) noexcept {
        return static_cast<NativeType*>(static_cast<void*>(wrapper));
    }

    static constexpr const NativeType* asNative(const WrapperType* wrapper) noexcept {
        return static_cast<const NativeType*>(static_cast<const void*>(wrapper));
    }

    static constexpr NativeType& asNative(WrapperType& wrapper) noexcept {
        return *asNative(&wrapper);
    }

    static constexpr const NativeType& asNative(const WrapperType& wrapper) noexcept {
        return *asNative(&wrapper);
    }
};

}  // namespace detail

/**
 * @ingroup Wrapper
 * @{
 */

/// Cast native object pointers to Wrapper object pointers.
/// This is especially helpful to avoid copies in getter methods of composed types.
/// @see https://github.com/open62541pp/open62541pp/issues/30
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr WrapperType* asWrapper(NativeType* native) noexcept {
    return detail::WrapperConversion<WrapperType>::asWrapper(native);
}

/// @copydoc asWrapper(NativeType*)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr const WrapperType* asWrapper(const NativeType* native) noexcept {
    return detail::WrapperConversion<WrapperType>::asWrapper(native);
}

/// Cast native object references to Wrapper object references.
/// @copydetails asWrapper(NativeType*)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr WrapperType& asWrapper(NativeType& native) noexcept {
    return detail::WrapperConversion<WrapperType>::asWrapper(native);
}

/// @copydoc asWrapper(NativeType&)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr const WrapperType& asWrapper(const NativeType& native) noexcept {
    return detail::WrapperConversion<WrapperType>::asWrapper(native);
}

/// Cast Wrapper object pointers to native object pointers.
/// @copydoc detail::WrapperConversion
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr NativeType* asNative(WrapperType* wrapper) noexcept {
    return detail::WrapperConversion<WrapperType>::asNative(wrapper);
}

/// @copydoc asNative(WrapperType*)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr const NativeType* asNative(const WrapperType* wrapper) noexcept {
    return detail::WrapperConversion<WrapperType>::asNative(wrapper);
}

/// Cast Wrapper object references to native object references.
/// @copydetails asNative(WrapperType*)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr NativeType& asNative(WrapperType& wrapper) noexcept {
    return detail::WrapperConversion<WrapperType>::asNative(wrapper);
}

/// @copydoc asNative(WrapperType&)
template <typename WrapperType, typename NativeType = typename WrapperType::NativeType>
constexpr const NativeType& asNative(const WrapperType& wrapper) noexcept {
    return detail::WrapperConversion<WrapperType>::asNative(wrapper);
}

/**
 * @}
 */

}  // namespace opcua
