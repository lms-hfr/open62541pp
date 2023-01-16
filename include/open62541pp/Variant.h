#pragma once

#include <cassert>
#include <cstdint>
#include <iterator>  // distance
#include <optional>
#include <vector>

#include "open62541pp/ErrorHandling.h"
#include "open62541pp/Helper.h"
#include "open62541pp/TypeConverter.h"
#include "open62541pp/TypeWrapper.h"
#include "open62541pp/Types.h"
#include "open62541pp/open62541.h"

namespace opcua {

// forward declarations
class NodeId;

/**
 * UA_Variant wrapper class.
 */
class Variant : public TypeWrapper<UA_Variant, Type::Variant> {
public:
    using BaseClass::BaseClass;  // inherit contructors

    /// Check if variant is empty
    bool isEmpty() const noexcept;
    /// Check if variant is a scalar
    bool isScalar() const noexcept;
    /// Check if variant is an array
    bool isArray() const noexcept;

    /// Check if variant type is equal to data type
    bool isType(const UA_DataType* type) const noexcept;
    /// Check if variant type is equal to type enum
    bool isType(Type type) const noexcept;
    /// Check if variant type is equal to data type node id
    bool isType(const NodeId& id) const noexcept;

    /// Get variant type
    std::optional<Type> getVariantType() const noexcept;

    /// Get reference to scalar value with given template type.
    /// @exception BadVariantAccess If the variant is not a scalar or not convertible to `T`.
    template <typename T>
    T& getScalar();

    /// Get copy of scalar value with given template type.
    /// @exception BadVariantAccess If the variant is not a scalar or not convertible to `T`.
    template <typename T>
    T getScalarCopy() const;

    /// Get array length or 0 if variant is not an array.
    size_t getArrayLength() const noexcept;

    /// Get array dimensions.
    std::vector<uint32_t> getArrayDimensions() const;

    template <typename T>
    T* getArray();

    /// Get copy of array with given template type and return it as a std::vector.
    /// @exception BadVariantAccess If the variant is not an array or not convertible to `T`.
    template <typename T>
    std::vector<T> getArrayCopy() const;

    /// Assign scalar value to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setScalar(T& value) noexcept;

    /// Copy scalar value to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setScalarCopy(const T& value);

    /// Assign array (raw) to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setArray(T* array, size_t size) noexcept;

    /// Assign array (std::vector) to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setArray(std::vector<T>& array) noexcept;

    /// Copy range of elements as array to variant.
    template <typename InputIt, Type type = detail::guessTypeFromIterator<InputIt>()>
    void setArrayCopy(InputIt first, InputIt last);

    /// Copy array (raw) to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setArrayCopy(const T* array, size_t size);

    /// Copy array (std::vector) to variant.
    template <typename T, Type type = detail::guessType<T>()>
    void setArrayCopy(const std::vector<T>& array);

private:
    void checkIsScalar() const;
    void checkIsArray() const;

    template <typename T>
    void checkReturnType() const {
        const auto optType = getVariantType();
        if (!optType || !detail::isValidTypeCombination<T>(*optType)) {
            throw BadVariantAccess("Variant does not contain a value convertible to template type");
        }
    }

    void setScalarImpl(void* value, const UA_DataType* type, bool own = false) noexcept;
    void setScalarCopyImpl(const void* value, const UA_DataType* type);
    void setArrayImpl(void* array, size_t size, const UA_DataType* type, bool own = false) noexcept;
    void setArrayCopyImpl(const void* array, size_t size, const UA_DataType* type);
};

/* ---------------------------------------------------------------------------------------------- */

template <typename T>
T& Variant::getScalar() {
    static_assert(
        detail::isNativeType<T>(), "Template type must be a native type to get scalar without copy"
    );
    checkIsScalar();
    checkReturnType<T>();
    assert(sizeof(T) == handle()->type->memSize);  // NOLINT
    return *static_cast<T*>(handle()->data);
}

template <typename T>
T Variant::getScalarCopy() const {
    checkIsScalar();
    checkReturnType<T>();
    return detail::fromNative<T>(handle()->data, getVariantType().value());
}

template <typename T>
T* Variant::getArray() {
    static_assert(
        detail::isNativeType<T>(), "Template type must be a native type to get array without copy"
    );
    checkIsArray();
    checkReturnType<T>();
    assert(sizeof(T) == handle()->type->memSize);  // NOLINT
    return *static_cast<T*>(handle()->data);
}

template <typename T>
std::vector<T> Variant::getArrayCopy() const {
    checkIsArray();
    checkReturnType<T>();
    return detail::fromNativeArray<T>(
        handle()->data, handle()->arrayLength, getVariantType().value()
    );
}

template <typename T, Type type>
void Variant::setScalar(T& value) noexcept {
    detail::assertTypeCombination<T, type>();
    static_assert(
        detail::isNativeType<T>() || detail::IsTypeWrapper<T>::value,
        "Template type must be convertible to native type to assign scalar without copy"
    );
    if constexpr (detail::IsTypeWrapper<T>::value) {
        setScalarImpl(value.handle(), detail::getUaDataType(type));
    } else {
        setScalarImpl(&value, detail::getUaDataType(type));
    }
}

template <typename T, Type type>
void Variant::setScalarCopy(const T& value) {
    detail::assertTypeCombination<T, type>();
    setScalarImpl(
        detail::toNativeAlloc<T, type>(value),
        detail::getUaDataType(type),
        true  // move ownership
    );
}

template <typename T, Type type>
void Variant::setArray(T* array, size_t size) noexcept {
    detail::assertTypeCombination<T, type>();
    static_assert(
        detail::isNativeType<T>(),
        "Template type must be a native type to assign array without copy"
    );
    setArrayImpl(array, size, detail::getUaDataType(type));
}

template <typename T, Type type>
void Variant::setArray(std::vector<T>& array) noexcept {
    setArray<T, type>(array.data(), array.size());
}

template <typename InputIt, Type type>
void Variant::setArrayCopy(InputIt first, InputIt last) {
    using ValueType = typename std::iterator_traits<InputIt>::value_type;
    detail::assertTypeCombination<ValueType, type>();
    setArrayImpl(
        detail::toNativeArrayAlloc<InputIt, type>(first, last),
        std::distance(first, last),
        detail::getUaDataType(type),
        true  // move ownership
    );
}

template <typename T, Type type>
void Variant::setArrayCopy(const T* array, size_t size) {
    detail::assertTypeCombination<T, type>();
    if constexpr (detail::isNativeType<T>()) {
        setArrayCopyImpl(array, size, detail::getUaDataType(type));
    } else {
        setArrayCopy<const T*, type>(array, array + size);
    }
}

template <typename T, Type type>
void Variant::setArrayCopy(const std::vector<T>& array) {
    setArrayCopy<T, type>(array.data(), array.size());
}

}  // namespace opcua
