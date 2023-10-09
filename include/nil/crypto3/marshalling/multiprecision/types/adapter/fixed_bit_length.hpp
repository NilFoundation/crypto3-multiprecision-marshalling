//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MARSHALLING_FIXED_BIT_LENGTH_HPP
#define CRYPTO3_MARSHALLING_FIXED_BIT_LENGTH_HPP

#include <nil/crypto3/marshalling/multiprecision/types/adapter/fixed_bit_length.hpp>

#include <limits>

#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/size_to_type.hpp>
#include <nil/crypto3/marshalling/multiprecision/processing/integral.hpp>


namespace nil {
    namespace marshalling {
        namespace types {
            namespace adapter {

                template<std::size_t TLen, typename TBase>
                class fixed_bit_length<
                    TLen,
                    TBase,
                    std::enable_if_t<
                        nil::crypto3::multiprecision::is_number<typename TBase::value_type>::value
                        && nil::crypto3::multiprecision::backends::is_fixed_precision<typename TBase::value_type::backend_type>::value
                    >
                > : public TBase {

                    using base_impl_type = TBase;
                    using base_serialized_type = typename base_impl_type::serialized_type;

                    static const std::size_t _bit_length = TLen;
                    static_assert(0 < _bit_length, "Bit length is expected to be greater than 0");
                    static_assert(_bit_length <= std::numeric_limits<base_serialized_type>::digits, "The provided length limit is too big");

                    static const std::size_t byte_length
                        = nil::marshalling::processing::bit_size_to_byte_size<_bit_length>::value;

                    static constexpr bool is_signed = std::numeric_limits<base_serialized_type>::is_signed;
                    // Multiprecision has no support for serialization signed values yet
                    static_assert(!is_signed, "Signed base class for fixed_bit_length is not supported");

                public:
                    using value_type = typename base_impl_type::value_type;
                    using serialized_type = typename crypto3::marshalling::processing::size_to_type<_bit_length, is_signed>::type;

                    using endian_type = typename base_impl_type::endian_type;

                    fixed_bit_length() = default;

                    explicit fixed_bit_length(const value_type &val) : base_impl_type(val) {
                    }

                    fixed_bit_length(const fixed_bit_length &) = default;

                    fixed_bit_length(fixed_bit_length &&) = default;

                    fixed_bit_length &operator=(const fixed_bit_length &) = default;

                    fixed_bit_length &operator=(fixed_bit_length &&) = default;

                    static constexpr std::size_t length() {
                        return bit_length() / 8 + ((bit_length() % 8) ? 1 : 0);;
                    }

                    static constexpr std::size_t min_length() {
                        return length();
                    }

                    static constexpr std::size_t max_length() {
                        return length();
                    }

                    static constexpr std::size_t bit_length() {
                        return _bit_length;
                    }

                    static constexpr std::size_t min_bit_length() {
                        return bit_length();
                    }

                    static constexpr std::size_t max_bit_length() {
                        return bit_length();
                    }

                    static constexpr serialized_type to_serialized(value_type val) {
                        serialized_type serialized = static_cast<serialized_type>(base_impl_type::to_serialized(val));
                        if constexpr (is_signed) {
                            if (val < 0) {
                                crypto3::multiprecision::bit_set(
                                    serialized,
                                    bit_length()-1
                                );
                            } else {
                                crypto3::multiprecision::bit_unset(
                                    serialized,
                                    bit_length()-1
                                );
                            }
                        }
                        return serialized;
                    }

                    static constexpr value_type from_serialized(serialized_type val) {
                        value_type deserialized = base_impl_type::from_serialized(val);
                        if constexpr (is_signed) {
                            if (crypto3::multiprecision::bit_test(deserialized, bit_length()-1)) {
                                value_type mask = value_type(-1) << bit_length();
                                return deserialized | mask;
                            } else {
                                return deserialized;
                            }
                        } else {
                            return deserialized;
                        }
                    }

                    template<typename TIter>
                    nil::marshalling::status_type read(TIter &iter, std::size_t size) {
                        if (size < length()) {
                            return nil::marshalling::status_type::not_enough_data;
                        }

                        read_no_status(iter);
                        return nil::marshalling::status_type::success;
                    }

                    template<typename TIter>
                    void read_no_status(TIter &iter) {
                        serialized_type serializedValue =
                            crypto3::marshalling::processing::read_data<
                                serialized_type,
                                typename base_impl_type::endian_type
                            >(iter, _bit_length);
                        base_impl_type::value() = from_serialized(serializedValue);
                    }

                    template<typename TIter>
                    nil::marshalling::status_type write(TIter &iter, std::size_t size) const {
                        if (size < length()) {
                            return nil::marshalling::status_type::buffer_overflow;
                        }

                        write_no_status(iter);
                        return nil::marshalling::status_type::success;
                    }

                    template<typename TIter>
                    void write_no_status(TIter &iter) const {
                        crypto3::marshalling::processing::write_data<
                            _bit_length,
                            typename base_impl_type::endian_type
                        >(to_serialized(base_impl_type::value()), iter);
                    }
                };

            }    // namespace adapter
        }    // namespace types
    }    // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_FIXED_BIT_LENGTH_HPP
