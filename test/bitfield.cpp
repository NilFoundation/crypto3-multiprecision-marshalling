//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_bitwise_test

#include <iostream>
#include <iomanip>

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/multiprecision/processing/size_to_type.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/bitfield.hpp>
#include "utils.h"

template<size_t FixedBitLength,
         size_t BaseTypeBitLength = 1024,
         bool IsSigned = false,
         typename Endianness = nil::marshalling::option::big_endian>
using integral_type = nil::crypto3::marshalling::types::integral<
    nil::marshalling::field_type<Endianness>,
    typename nil::crypto3::marshalling::processing::size_to_type<BaseTypeBitLength, IsSigned>::type,
    nil::marshalling::option::fixed_bit_length<FixedBitLength>>;

template<typename TField>
void test_buffer_equality(const TField &field, const std::vector<std::uint8_t> &expectedBuffer) {
    nil::marshalling::status_type status;
    std::vector<unsigned char> outDataBuf = nil::marshalling::pack(field, status);

    BOOST_CHECK(std::equal(expectedBuffer.begin(), expectedBuffer.end(), outDataBuf.begin()));
}

template<typename TField>
void test_round_trip(const TField &field,
                     nil::marshalling::status_type expectedStatus = nil::marshalling::status_type::success) {
    nil::marshalling::status_type status;
    std::vector<char> outDataBuf = nil::marshalling::pack(field, status);

    std::cout << "final blob: ";
    print_byteblob(outDataBuf.begin(), outDataBuf.end());

    TField newField = nil::marshalling::pack<TField>(outDataBuf, status);

    BOOST_CHECK(status == expectedStatus);
    BOOST_CHECK(field == newField);
    BOOST_CHECK(field.value() == newField.value());
}

BOOST_AUTO_TEST_SUITE(bitfield_test_suite)

BOOST_AUTO_TEST_CASE(test_0) {
    using integral_type_0 = integral_type<512>;
    using integral_type_1 = integral_type<512>;
    using BitfieldMembers = std::tuple<integral_type_0, integral_type_1>;
    using testing_type =
        nil::crypto3::marshalling::types::bitfield<nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                                   BitfieldMembers>;

    static_assert(!testing_type::is_version_dependent(), "Invalid version dependency assumption");

    testing_type field;
    static_cast<void>(field);

    BOOST_CHECK(field.length() == 128U);
    BOOST_CHECK(field.member_bit_length<0>() == 512U);
    BOOST_CHECK(field.member_bit_length<1>() == 512U);

    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    mem1.value() = 0x1;
    BOOST_CHECK(mem1.value() == 0x1);
    auto &mem2 = std::get<1>(members);
    mem2.value() = 0xABCDEF1234567890;
    BOOST_CHECK(mem2.value() == 0xABCDEF1234567890);

    test_round_trip(field);
}

// Doesn't work, signed values serialization is unsupported
// BOOST_AUTO_TEST_CASE(test_1) {
//     using integral_type_0 = integral_type<5, 128, /*IsSigned=*/ true>;
//     using integral_type_1 = integral_type<3, 256, /*IsSigned=*/ true>;
//     using BitfieldMembers =
//         std::tuple<
//             integral_type_0,
//             integral_type_1
//         >;
//     using testing_type =
//         nil::crypto3::marshalling::types::bitfield<
//             nil::marshalling::field_type<
//                 nil::marshalling::option::big_endian
//             >,
//             BitfieldMembers
//         >;

//     testing_type field;
//     static_cast<void>(field);
//     BOOST_CHECK(field.length() == 1U);
//     BOOST_CHECK(field.member_bit_length<0>() == 5U);
//     BOOST_CHECK(field.member_bit_length<1>() == 3U);

//     auto &members = field.value();
//     auto &mem1 = std::get<0>(members);
//     auto &mem2 = std::get<1>(members);
//     mem1.value() = -0x7;
//     mem2.value() = -0x2;
//     BOOST_CHECK(mem1.value() == -0x7);
//     BOOST_CHECK(mem2.value() == -0x2);
//     test_round_trip(field);
// }

BOOST_AUTO_TEST_CASE(test_2) {
    using integral_type_0 = integral_type<1, 1024, false, nil::marshalling::option::little_endian>;
    using integral_type_1 = integral_type<511, 1024, false, nil::marshalling::option::little_endian>;
    using BitfieldMembers = std::tuple<integral_type_0, integral_type_1>;
    using testing_type =
        nil::crypto3::marshalling::types::bitfield<nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                                   BitfieldMembers>;

    testing_type field;
    static_cast<void>(field);

    BOOST_CHECK(field.length() == 64U);
    BOOST_CHECK(field.member_bit_length<0>() == 1U);
    BOOST_CHECK(field.member_bit_length<1>() == 511U);

    auto &members = field.value();
    auto &mem1 = std::get<0>(members);
    mem1.value() = 0x1;
    BOOST_CHECK(mem1.value() == 0x1);
    auto &mem2 = std::get<1>(members);
    nil::crypto3::multiprecision::uint1024_t max_val = 1;
    max_val = (max_val << 511) - 1;
    mem2.value() = max_val;
    BOOST_CHECK(mem2.value() == max_val);

    test_round_trip(field);
}

BOOST_AUTO_TEST_CASE(test_3) {
    using integral_type_0 = integral_type<2, 123, false, nil::marshalling::option::big_endian>;
    using integral_type_1 = integral_type<3, 124, false, nil::marshalling::option::little_endian>;
    using integral_type_2 = integral_type<4, 125, false, nil::marshalling::option::little_endian>;
    using integral_type_3 = integral_type<5, 126, false, nil::marshalling::option::big_endian>;
    using integral_type_4 = integral_type<6, 127, false, nil::marshalling::option::big_endian>;
    using integral_type_5 = integral_type<7, 128, false, nil::marshalling::option::big_endian>;
    using integral_type_6 = integral_type<8, 129, false, nil::marshalling::option::little_endian>;
    using integral_type_7 = integral_type<9, 130, false, nil::marshalling::option::little_endian>;
    using integral_type_8 = integral_type<10, 12, false, nil::marshalling::option::big_endian>;
    using integral_type_9 = integral_type<10, 321, false, nil::marshalling::option::little_endian>;

    using BitfieldMembers = std::tuple<integral_type_0,
                                       integral_type_1,
                                       integral_type_2,
                                       integral_type_3,
                                       integral_type_4,
                                       integral_type_5,
                                       integral_type_6,
                                       integral_type_7,
                                       integral_type_8,
                                       integral_type_9>;
    using testing_type = nil::crypto3::marshalling::types::
        bitfield<nil::marshalling::field_type<nil::marshalling::option::little_endian>, BitfieldMembers>;

    testing_type field;
    static_cast<void>(field);

    BOOST_CHECK(field.length() == 8U);
    BOOST_CHECK(field.member_bit_length<0>() == 2U);
    BOOST_CHECK(field.member_bit_length<1>() == 3U);
    BOOST_CHECK(field.member_bit_length<2>() == 4U);
    BOOST_CHECK(field.member_bit_length<3>() == 5U);
    BOOST_CHECK(field.member_bit_length<4>() == 6U);
    BOOST_CHECK(field.member_bit_length<5>() == 7U);
    BOOST_CHECK(field.member_bit_length<6>() == 8U);
    BOOST_CHECK(field.member_bit_length<7>() == 9U);
    BOOST_CHECK(field.member_bit_length<8>() == 10U);
    BOOST_CHECK(field.member_bit_length<9>() == 10U);

    auto &members = field.value();
    std::get<0>(members).value() = 0x0;
    std::get<1>(members).value() = 0x1;
    std::get<2>(members).value() = 0x2;
    std::get<3>(members).value() = 0x3;
    std::get<4>(members).value() = 0x4;
    std::get<5>(members).value() = 0x5;
    std::get<6>(members).value() = 0x6;
    std::get<7>(members).value() = 0x7;
    std::get<8>(members).value() = 0x8;
    std::get<9>(members).value() = 0x9;

    test_round_trip(field);

    BOOST_CHECK(std::get<0>(members).value() == 0x0);
    BOOST_CHECK(std::get<1>(members).value() == 0x1);
    BOOST_CHECK(std::get<2>(members).value() == 0x2);
    BOOST_CHECK(std::get<3>(members).value() == 0x3);
    BOOST_CHECK(std::get<4>(members).value() == 0x4);
    BOOST_CHECK(std::get<5>(members).value() == 0x5);
    BOOST_CHECK(std::get<6>(members).value() == 0x6);
    BOOST_CHECK(std::get<7>(members).value() == 0x7);
    BOOST_CHECK(std::get<8>(members).value() == 0x8);
    BOOST_CHECK(std::get<9>(members).value() == 0x9);
}

BOOST_AUTO_TEST_CASE(test_bitfield_endianness) {
    using integral_type_0 = integral_type<3, 3, false, nil::marshalling::option::big_endian>;
    using integral_type_1 = integral_type<16, 16, false, nil::marshalling::option::big_endian>;
    using integral_type_2 = integral_type<5, 5, false, nil::marshalling::option::big_endian>;

    using BitfieldMembers = std::tuple<integral_type_0, integral_type_1, integral_type_2>;
    using testing_type_big_endian =
        nil::crypto3::marshalling::types::bitfield<nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                                   BitfieldMembers>;

    testing_type_big_endian big_endian_field;
    static_cast<void>(big_endian_field);

    auto &members_be = big_endian_field.value();
    std::get<0>(members_be).value() = 0b000;
    std::get<1>(members_be).value() = 0b1110110100000001;
    std::get<2>(members_be).value() = 0b00000;

    test_buffer_equality(big_endian_field, {0b00000111, 0b01101000, 0b00001000});

    using testing_type_little_endian = nil::crypto3::marshalling::types::
        bitfield<nil::marshalling::field_type<nil::marshalling::option::little_endian>, BitfieldMembers>;

    testing_type_little_endian little_endian_field;

    auto &members_le = little_endian_field.value();
    std::get<0>(members_le).value() = 0b000;
    std::get<1>(members_le).value() = 0b1110110100000001;
    std::get<2>(members_le).value() = 0b00000;

    test_buffer_equality(little_endian_field, {0b00001000, 0b01101000, 0b00000111});

    test_round_trip(little_endian_field);
}

BOOST_AUTO_TEST_CASE(test_inner_field_endianness) {
    using integral_type_0 = integral_type<3, 3, false, nil::marshalling::option::big_endian>;
    // XXX: inner endianness does not affect serialization. Upstream bitfield does not do this neither
    using integral_type_1 = integral_type<16, 16, false, nil::marshalling::option::little_endian>;
    using integral_type_2 = integral_type<5, 5, false, nil::marshalling::option::big_endian>;

    using BitfieldMembers = std::tuple<integral_type_0, integral_type_1, integral_type_2>;
    using testing_type_big_endian =
        nil::crypto3::marshalling::types::bitfield<nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                                   BitfieldMembers>;

    testing_type_big_endian big_endian_field;
    static_cast<void>(big_endian_field);

    auto &members_be = big_endian_field.value();
    std::get<0>(members_be).value() = 0b000;
    std::get<1>(members_be).value() = 0b1110110100000001;
    std::get<2>(members_be).value() = 0b00000;

    test_buffer_equality(big_endian_field, {0b00000111, 0b01101000, 0b00001000});
}

BOOST_AUTO_TEST_SUITE_END()
