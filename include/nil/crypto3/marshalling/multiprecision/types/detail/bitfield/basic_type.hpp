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

#ifndef CRYPTO3_MARSHALLING_BASIC_BITFIELD_DEFINITION_HPP
#define CRYPTO3_MARSHALLING_BASIC_BITFIELD_DEFINITION_HPP

#include <boost/type_traits/is_integral.hpp>
#include <nil/marshalling/processing/tuple.hpp>
#include <nil/marshalling/types/bitfield/type_traits.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/size_to_type.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                namespace detail {

                    template<typename TFieldBase, typename TMembers>
                    class basic_bitfield : public TFieldBase {
                        using base_impl_type = TFieldBase;

                        static_assert(nil::detail::is_tuple<TMembers>::value,
                                      "TMembers is expected to be a tuple of BitfieldMember<...>");

                        static_assert(1U < std::tuple_size<TMembers>::value,
                                      "Number of members is expected to be at least 2.");

                        static constexpr std::size_t total_bits =
                            nil::marshalling::types::detail::calc_bit_length<TMembers>();
                        static_assert((total_bits % std::numeric_limits<std::uint8_t>::digits) == 0,
                                      "Wrong number of total bits, it should be devidable by 8");

                        static const std::size_t total_bytes = total_bits / std::numeric_limits<std::uint8_t>::digits;
                        static_assert(0U < total_bytes, "Serialised length is expected to be greater than 0");

                        using serialized_type = typename processing::size_to_type<total_bits>::type;

                    public:
                        using endian_type = typename base_impl_type::endian_type;
                        using version_type = typename base_impl_type::version_type;
                        using value_type = TMembers;

                        basic_bitfield() = default;

                        explicit basic_bitfield(const value_type &val) : members_(val) {
                        }

                        explicit basic_bitfield(value_type &&val) : members_(std::move(val)) {
                        }

                        const value_type &value() const {
                            return members_;
                        }

                        value_type &value() {
                            return members_;
                        }

                        static constexpr std::size_t length() {
                            return total_bytes;
                        }

                        static constexpr std::size_t min_length() {
                            return length();
                        }

                        static constexpr std::size_t max_length() {
                            return length();
                        }

                        template<typename TIter>
                        nil::marshalling::status_type read(TIter &iter, std::size_t size) {
                            if (size < length()) {
                                return nil::marshalling::status_type::not_enough_data;
                            }

                            serialized_type serValue =
                                processing::read_data<total_bits, serialized_type, endian_type>(iter);
                            nil::marshalling::status_type es = nil::marshalling::status_type::success;
                            nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                                members_, read_helper(serValue, es));
                            return es;
                        }

                        template<typename TIter>
                        void read_no_status(TIter &iter) {
                            serialized_type serValue =
                                processing::read_data<total_bits, serialized_type, endian_type>(iter);
                            nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                                members_, read_no_status_helper(serValue));
                        }

                        template<typename TIter>
                        nil::marshalling::status_type write(TIter &iter, std::size_t size) const {
                            if (size < length()) {
                                return nil::marshalling::status_type::buffer_overflow;
                            }

                            serialized_type serValue = 0;
                            nil::marshalling::status_type es = nil::marshalling::status_type::success;
                            nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                                members_, write_helper(serValue, es));
                            if (es == nil::marshalling::status_type::success) {
                                processing::write_data<total_bits, endian_type>(serValue, iter);
                            }
                            return es;
                        }

                        template<typename TIter>
                        void write_no_status(TIter &iter) const {
                            serialized_type serValue = 0;
                            nil::marshalling::processing::tuple_for_each_with_template_param_idx(
                                members_, write_no_status_helper(serValue));
                            processing::write_data<total_bits, endian_type>(serValue, iter);
                        }

                        constexpr bool valid() const {
                            return nil::marshalling::processing::tuple_accumulate(members_, true, valid_helper());
                        }

                        bool refresh() {
                            return nil::marshalling::processing::tuple_accumulate(members_, false, refresh_helper());
                        }

                        template<std::size_t TIdx>
                        static constexpr std::size_t member_bit_length() {
                            static_assert(TIdx < std::tuple_size<value_type>::value, "Index exceeds number of fields");

                            using field_type = typename std::tuple_element<TIdx, value_type>::type;
                            return nil::marshalling::types::detail::bitfield_member_length_retriever<field_type>::value;
                        }

                        static constexpr bool is_version_dependent() {
                            return nil::marshalling::types::detail::common_funcs::are_members_version_dependent<
                                value_type>();
                        }

                        bool set_version(version_type version) {
                            return nil::marshalling::types::detail::common_funcs::set_version_for_members(value(),
                                                                                                          version);
                        }

                    private:
                        class read_helper {
                        public:
                            read_helper(serialized_type val, nil::marshalling::status_type &es) : value_(val), es_(es) {
                            }

                            template<std::size_t TIdx, typename TFieldParam>
                            void operator()(TFieldParam &&field) {
                                if (es_ != nil::marshalling::status_type::success) {
                                    return;
                                }

                                using field_type = typename std::decay<TFieldParam>::type;
                                static const auto Pos =
                                    nil::marshalling::types::detail::get_member_shift_pos<TIdx, value_type>();
                                static const auto Mask =
                                    (static_cast<serialized_type>(1U)
                                     << nil::marshalling::types::detail::bitfield_member_length_retriever<
                                            field_type>::value) -
                                    1;

                                auto fieldSerValue = static_cast<serialized_type>((value_ >> Pos) & Mask);

                                static_assert(field_type::min_length() == field_type::max_length(),
                                              "basic_bitfield doesn't support members with variable length");

                                static const std::size_t max_length = field_type::max_length();
                                std::uint8_t buf[max_length];
                                auto writeIter = std::begin(buf);

                                processing::write_data<field_type::bit_length(), typename field_type::endian_type>(
                                    fieldSerValue, writeIter);

                                auto readIter = std::cbegin(buf);
                                es_ = field.read(readIter, field_type::bit_length());
                            }

                        private:
                            serialized_type value_;
                            nil::marshalling::status_type &es_;
                        };

                        class read_no_status_helper {
                        public:
                            read_no_status_helper(serialized_type val) : value_(val) {
                            }

                            template<std::size_t TIdx, typename TFieldParam>
                            void operator()(TFieldParam &&field) {
                                using field_type = typename std::decay<decltype(field)>::type;
                                using FieldOptions = typename field_type::parsed_options_type;
                                static const auto Pos =
                                    nil::marshalling::types::detail::get_member_shift_pos<TIdx, value_type>();
                                static const auto Mask =
                                    (static_cast<serialized_type>(1) << FieldOptions::fixed_bit_length) - 1;

                                auto fieldSerValue = static_cast<serialized_type>((value_ >> Pos) & Mask);

                                static_assert(field_type::min_length() == field_type::max_length(),
                                              "basic_bitfield doesn't support members with variable length");

                                std::uint8_t buf[field_type::max_length()];
                                auto writeIter = std::begin(buf);
                                processing::write_data<field_type::bit_length(), typename field_type::endian_type>(
                                    fieldSerValue, writeIter);

                                auto readIter = std::cbegin(buf);
                                field.read_no_status(readIter);
                            }

                        private:
                            serialized_type value_;
                        };

                        class write_helper {
                        public:
                            write_helper(serialized_type &val, nil::marshalling::status_type &es) :
                                value_(val), es_(es) {
                            }

                            template<std::size_t TIdx, typename TFieldParam>
                            void operator()(TFieldParam &&field) {
                                if (es_ != nil::marshalling::status_type::success) {
                                    return;
                                }

                                using field_type = typename std::decay<decltype(field)>::type;

                                static_assert(field_type::min_length() == field_type::max_length(),
                                              "basic_bitfield supports fixed length members only.");

                                std::uint8_t buf[field_type::max_length()];
                                auto writeIter = std::begin(buf);

                                nil::marshalling::status_type status;
                                es_ =
                                    field.write(writeIter, field_type::bit_length());    // TODO: len as template param?

                                if (es_ != nil::marshalling::status_type::success) {
                                    return;
                                }

                                auto readIter = std::cbegin(buf);
                                serialized_type fieldSerValue =
                                    processing::read_data<field_type::bit_length(),
                                                          serialized_type,
                                                          typename field_type::endian_type>(readIter);

                                static const auto Pos =
                                    nil::marshalling::types::detail::get_member_shift_pos<TIdx, value_type>();
                                static const auto Mask =
                                    (static_cast<serialized_type>(1U)
                                     << nil::marshalling::types::detail::bitfield_member_length_retriever<
                                            field_type>::value) -
                                    1;

                                static const auto ClearMask = ~(Mask << Pos);

                                auto valueMask = (fieldSerValue & Mask) << Pos;

                                value_ &= ClearMask;
                                value_ |= valueMask;
                            }

                        private:
                            serialized_type &value_;
                            nil::marshalling::status_type &es_;
                        };

                        class write_no_status_helper {
                        public:
                            write_no_status_helper(serialized_type &val) : value_(val) {
                            }

                            template<std::size_t TIdx, typename TFieldParam>
                            void operator()(TFieldParam &&field) {

                                using field_type = typename std::decay<decltype(field)>::type;

                                static_assert(field_type::min_length() == field_type::max_length(),
                                              "basic_bitfield supports fixed length members only.");

                                static const std::size_t max_length = field_type::max_length();
                                std::uint8_t buf[max_length];
                                auto writeIter = std::begin(buf);
                                field.write_no_status(writeIter);

                                auto readIter = std::cbegin(buf);
                                auto fieldSerValue = processing::read_data<field_type::bit_length(),
                                                                           serialized_type,
                                                                           typename field_type::endian_type>(readIter);

                                using FieldOptions = typename field_type::parsed_options_type;
                                static const auto Pos =
                                    nil::marshalling::types::detail::get_member_shift_pos<TIdx, value_type>();
                                static const auto Mask =
                                    (static_cast<serialized_type>(1) << FieldOptions::fixed_bit_length) - 1;

                                static const auto ClearMask = ~(Mask << Pos);

                                auto valueMask = (static_cast<serialized_type>(fieldSerValue) & Mask) << Pos;

                                value_ &= ClearMask;
                                value_ |= valueMask;
                            }

                        private:
                            serialized_type &value_;
                        };

                        struct valid_helper {
                            template<typename TFieldParam>
                            bool operator()(bool soFar, const TFieldParam &field) {
                                return soFar && field.valid();
                            }
                        };

                        struct refresh_helper {
                            template<typename TFieldParam>
                            bool operator()(bool soFar, TFieldParam &field) {
                                return field.refresh() || soFar;
                            }
                        };

                        value_type members_;
                    };

                }    // namespace detail
            }        // namespace types
        }            // namespace marshalling
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_BASIC_BITFIELD_DEFINITION_HPP
