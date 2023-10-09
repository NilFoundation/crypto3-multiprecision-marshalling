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

#define BOOST_TEST_MODULE crypto3_marshalling_integral_test
// #define BOOST_TEST_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>
#include "utils.h"


template<class T, typename OutputType>
void test_round_trip_fixed_precision_big_endian(T val) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : 8 * sizeof(OutputType);
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::big_endian>, T>;
    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);
    std::vector<unit_type> cv;
    cv.resize(unitblob_size, 0x00);
    std::size_t begin_index = cv.size() - ((nil::crypto3::multiprecision::msb(val) + 1) / units_bits +
                                           (((nil::crypto3::multiprecision::msb(val) + 1) % units_bits) ? 1 : 0));

    export_bits(val, cv.begin() + begin_index, units_bits, true);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<nil::marshalling::option::big_endian>(cv, status);

    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<nil::marshalling::option::big_endian>(val, status);
    std::cout << "buffer of " << val << " is: ";
    print_byteblob(std::begin(test_cv), std::end(test_cv));
    // throw;

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_fixed_precision_little_endian(T val) {
    using namespace nil::crypto3::marshalling;
    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : 8 * sizeof(OutputType);
    using unit_type = OutputType;
    using integral_type = types::integral<nil::marshalling::field_type<nil::marshalling::option::little_endian>, T>;
    std::size_t unitblob_size =
        integral_type::bit_length() / units_bits + ((integral_type::bit_length() % units_bits) ? 1 : 0);

    std::vector<unit_type> cv;

    export_bits(val, std::back_inserter(cv), units_bits, false);
    cv.resize(unitblob_size, 0x00);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<nil::marshalling::option::little_endian>(cv, status);

    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<nil::marshalling::option::little_endian>(val, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_fixed_precision() {

    static_assert(nil::marshalling::is_compatible<T>::value);

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1; ++i) {
        T val = generate_random<T>();
        test_round_trip_fixed_precision_big_endian<T, OutputType>(val);
        test_round_trip_fixed_precision_little_endian<T, OutputType>(val);
    }
}

template<typename TEndianness, class T, typename OutputType>
void test_round_trip_non_fixed_precision(T val) {
    using namespace nil::crypto3::marshalling;

    std::size_t units_bits = std::is_same_v<OutputType, bool> ? 1 : CHAR_BIT * sizeof(OutputType);
    using unit_type = OutputType;

    std::vector<unit_type> cv;
    export_bits(val, std::back_inserter(cv), units_bits,
        std::is_same<TEndianness, nil::marshalling::option::big_endian>::value?true:false);

    nil::marshalling::status_type status;
    T test_val = nil::marshalling::pack<TEndianness>(cv, status);

    // std::cout << std::hex << test_val << '\n' << val << '\n';

    // std::cout << "bits:\n";
    // for(auto a : cv){
    //     std::cout << a;
    // }
    // std::cout << '\n';

    // for(auto a : test_cv){
    //     std::cout << a;
    // }
    // std::cout << '\n';


    BOOST_CHECK(val == test_val);
    BOOST_CHECK(status == nil::marshalling::status_type::success);

    std::vector<unit_type> test_cv = nil::marshalling::pack<TEndianness>(val, status);

    BOOST_CHECK(std::equal(test_cv.begin(), test_cv.end(), cv.begin()));
    BOOST_CHECK(status == nil::marshalling::status_type::success);
}

template<class T, typename OutputType>
void test_round_trip_non_fixed_precision() {

    static_assert(nil::marshalling::is_compatible<T>::value);

    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        T val = generate_random<T>();
        test_round_trip_non_fixed_precision<nil::marshalling::option::big_endian, T, OutputType>(val);
        test_round_trip_non_fixed_precision<nil::marshalling::option::little_endian, T, OutputType>(val);
    }
}

BOOST_AUTO_TEST_SUITE(integral_test_suite)

BOOST_AUTO_TEST_CASE(integral_cpp_int) {
    test_round_trip_non_fixed_precision<nil::crypto3::multiprecision::cpp_int, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_checked_int1024) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_int1024_t, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_uint512) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_uint512_t, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_64) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        64, 64, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>, unsigned char>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_23) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        23, 23, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>, unsigned char>();
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(integral_test_suite_bits)

BOOST_AUTO_TEST_CASE(integral_cpp_int_bits) {
    test_round_trip_non_fixed_precision<nil::crypto3::multiprecision::cpp_int, bool>();
}

BOOST_AUTO_TEST_CASE(integral_checked_int1024_bits) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_int1024_t, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_uint512_bits) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::checked_uint512_t, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_64_bits) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        64, 64, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_23_bits) {
    test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        23, 23, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>, bool>();
}

BOOST_AUTO_TEST_CASE(integral_cpp_int_backend_123_bits) {
    using signed_type = nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        123, 123, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::unchecked, void>>;
    std::cout << std::hex;
    std::cerr << std::hex;
    for (unsigned i = 0; i < 1000; ++i) {
        signed_type val = generate_random<signed_type, true>();
        nil::marshalling::status_type status;
        std::vector<std::uint8_t> cv = nil::marshalling::pack<nil::marshalling::option::big_endian>(val, status);
        signed_type new_val = nil::marshalling::pack<nil::marshalling::option::big_endian>(cv, status);
        BOOST_CHECK(new_val == val);
        std::cout << val << std::endl;
        print_byteblob(std::begin(cv), std::end(cv));
        // T test_val = nil::marshalling::pack<nil::marshalling::option::big_endian>(cv, status);
        // test_round_trip_fixed_precision_little_endian<signed_type, unsigned char>(val);
    }



    // BOOST_CHECK(val == test_val);
    // BOOST_CHECK(status == nil::marshalling::status_type::success);

    // std::vector<unit_type> test_cv = nil::marshalling::pack<nil::marshalling::option::big_endian>(val, status);
    // test_round_trip_fixed_precision<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
    //     123, 123, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::checked, void>>, bool>();
}

BOOST_AUTO_TEST_SUITE_END()
