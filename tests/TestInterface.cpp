#include "../src/AccessControlProcessFacility.h"

#include <cassert>
#include <sharemind/TestAssert.h>
#include <string>


using namespace sharemind;

namespace {

char const POLICY[] = "The policy";
char const OBJECT[] = "The object";

class Facility final: public AccessControlProcessFacility {

private: /* Methods: */

    AccessResult checkWithPredicates(
            PreparedPredicate const & rulesetNamePredicate,
            PreparedPredicate const * const * ptrs,
            std::size_t size) const final override
    {
        if (!size)
            return AccessResult::Unspecified;
        assert(ptrs);
        if (!rulesetNamePredicate(m_policy))
            return AccessResult::Unspecified;
        auto r = AccessResult::Unspecified;
        for (;; ++ptrs) {
            PreparedPredicate const & objectNamePredicate = **ptrs;
            if (objectNamePredicate(m_object))
                r = AccessResult::Allowed;
            if (!--size)
                break;
        }
        return r;
    }

    std::string const m_policy{POLICY};
    std::string const m_object{OBJECT};

};

enum class TestAccessResult { Allowed, Denied, Unspecified, Exception };

template <typename Policy, typename Object>
TestAccessResult test(Policy && policy, Object && object) {
    try {
        auto const r = Facility().check(std::forward<Policy>(policy),
                                        std::forward<Object>(object));
        if (r == AccessResult::Allowed) {
            return TestAccessResult::Allowed;
        } else if (r == AccessResult::Denied) {
            return TestAccessResult::Denied;
        } else {
            assert(r == AccessResult::Unspecified);
            return TestAccessResult::Unspecified;
        }
    } catch (...) {
        return TestAccessResult::Exception;
    }
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-member-function"
#endif
struct ThrowingRange {
    constexpr static char const * begin() { return nullptr; }
    constexpr static char const * end() { return nullptr; }
    static std::size_t size() { throw 42; }
};
#ifdef __clang__
#pragma clang diagnostic pop
#endif

} // anonymous namespace

#define TA(...) \
        SHAREMIND_TESTASSERT(test(__VA_ARGS__) == TestAccessResult::Allowed)
#define TU(...) \
    SHAREMIND_TESTASSERT(test(__VA_ARGS__) == TestAccessResult::Unspecified)
#define TE(...) \
        SHAREMIND_TESTASSERT(test(__VA_ARGS__) == TestAccessResult::Exception)
#define LIT(s) asLiteralStringRange(s)
#define NTCS(s) static_cast<char const *>(s)
#define STR(s) str_ ## s
#define THROW ThrowingRange()

int main() {
    std::string const & str_POLICY(POLICY);
    std::string const & str_OBJECT(OBJECT);
    TE(THROW, THROW);
    TE(THROW, OBJECT);
    TE(THROW, LIT(OBJECT));
    TE(THROW, NTCS(OBJECT));
    TE(THROW, STR(OBJECT));
    TU(POLICY, THROW);
    TU(POLICY, OBJECT);
    TU(POLICY, LIT(OBJECT));
    TU(POLICY, NTCS(OBJECT));
    TU(POLICY, STR(OBJECT));
    TE(LIT(POLICY), THROW);
    TU(LIT(POLICY), OBJECT);
    TA(LIT(POLICY), LIT(OBJECT));
    TA(LIT(POLICY), NTCS(OBJECT));
    TA(LIT(POLICY), STR(OBJECT));
    TE(NTCS(POLICY), THROW);
    TU(NTCS(POLICY), OBJECT);
    TA(NTCS(POLICY), LIT(OBJECT));
    TA(NTCS(POLICY), NTCS(OBJECT));
    TA(NTCS(POLICY), STR(OBJECT));
    TE(STR(POLICY), THROW);
    TU(STR(POLICY), OBJECT);
    TA(STR(POLICY), LIT(OBJECT));
    TA(STR(POLICY), NTCS(OBJECT));
    TA(STR(POLICY), STR(OBJECT));
}
