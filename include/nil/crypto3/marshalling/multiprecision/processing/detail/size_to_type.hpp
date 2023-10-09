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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP

#include <nil/crypto3/multiprecision/number.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {
                namespace detail {
                    /// @cond SKIP_DOC

                    using namespace multiprecision;

                    template<bool IsSigned>
                    constexpr cpp_integer_type select_magnitude_type() {
                        if constexpr (IsSigned) {
                            return signed_magnitude;
                        } else {
                            return unsigned_magnitude;
                        }
                    }

                    template<bool IsChecked>
                    constexpr cpp_int_check_type select_checked_type() {
                        if constexpr (IsChecked) {
                            return checked;
                        } else {
                            return unchecked;
                        }
                    }

                    /// @endcond

                }    // namespace detail
            }        // namespace processing
        }            // namespace marshalling
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP
