#pragma once

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>


template<class T>
struct unchecked_type {
    typedef T type;
};

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType,
         nil::crypto3::multiprecision::cpp_int_check_type Checked, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
struct unchecked_type<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, Checked, Allocator>,
    ExpressionTemplates>> {
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType,
                                                      nil::crypto3::multiprecision::unchecked, Allocator>,
        ExpressionTemplates>
        type;
};

template<class T, bool GenerateSigned = false>
T generate_random() {
    typedef typename unchecked_type<T>::type unchecked_T;

    static const unsigned limbs = std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_bounded ?
                                      std::numeric_limits<T>::digits / std::numeric_limits<unsigned>::digits + 3 :
                                      20;

    static boost::random::uniform_int_distribution<unsigned> ui(0, limbs);
    static boost::random::mt19937 gen;
    unchecked_T val = gen();
    unsigned lim = ui(gen);
    for (unsigned i = 0; i < lim; ++i) {
        val *= (gen.max)();
        val += gen();
    }

    if (GenerateSigned && std::numeric_limits<T>::is_signed) {
        static boost::random::uniform_int_distribution<int> sign_gen(-1, 1);
        int sign = sign_gen(gen);
        val *= sign;
    }

    return static_cast<T>(val);
}

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; ++it) {
        std::cout << "0x"
                  << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<unsigned char>(*it)) << " ";
    }
    std::cout << std::endl;
}
