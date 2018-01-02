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
            PreparedPredicate const * const * ptrs,
            std::size_t size) const noexcept final override
    {
        if (!size)
            return AccessResult::Unspecified;
        assert(ptrs);
        auto r = AccessResult::Unspecified;
        try {
            for (;;) {
                PreparedPredicate const & policyPredicate = **ptrs;
                PreparedPredicate const & objectPredicate = **++ptrs;
                if (policyPredicate(m_policy) && objectPredicate(m_object))
                    r = AccessResult::Allowed;
                if (!--size)
                    break;
                ++ptrs;
            }
        } catch (...) {
            return AccessResult::Denied;
        }
        return r;
    }

    std::string const m_policy{POLICY};
    std::string const m_object{OBJECT};

};

template <typename Policy, typename Object>
AccessResult test(Policy && policy, Object && object) {
    return Facility().check(std::forward<Policy>(policy),
                            std::forward<Object>(object));
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
        SHAREMIND_TESTASSERT(test(__VA_ARGS__) == AccessResult::Allowed)
#define TD(...) \
        SHAREMIND_TESTASSERT(test(__VA_ARGS__) == AccessResult::Denied)
#define TU(...) \
    SHAREMIND_TESTASSERT(test(__VA_ARGS__) == AccessResult::Unspecified)
#define LIT(s) asLiteralStringRange(s)
#define NTCS(s) static_cast<char const *>(s)
#define STR(s) str_ ## s
#define THROW ThrowingRange()

int main() {
    std::string const & str_POLICY(POLICY);
    std::string const & str_OBJECT(OBJECT);
    TD(THROW, THROW);
    TD(THROW, OBJECT);
    TD(THROW, LIT(OBJECT));
    TD(THROW, NTCS(OBJECT));
    TD(THROW, STR(OBJECT));
    TU(POLICY, THROW);
    TU(POLICY, OBJECT);
    TU(POLICY, LIT(OBJECT));
    TU(POLICY, NTCS(OBJECT));
    TU(POLICY, STR(OBJECT));
    TD(LIT(POLICY), THROW);
    TU(LIT(POLICY), OBJECT);
    TA(LIT(POLICY), LIT(OBJECT));
    TA(LIT(POLICY), NTCS(OBJECT));
    TA(LIT(POLICY), STR(OBJECT));
    TD(NTCS(POLICY), THROW);
    TU(NTCS(POLICY), OBJECT);
    TA(NTCS(POLICY), LIT(OBJECT));
    TA(NTCS(POLICY), NTCS(OBJECT));
    TA(NTCS(POLICY), STR(OBJECT));
    TD(STR(POLICY), THROW);
    TU(STR(POLICY), OBJECT);
    TA(STR(POLICY), LIT(OBJECT));
    TA(STR(POLICY), NTCS(OBJECT));
    TA(STR(POLICY), STR(OBJECT));
}
