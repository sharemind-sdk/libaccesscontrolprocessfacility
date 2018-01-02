/*
 * Copyright (C) Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#ifndef SHAREMIND_ACCESSCONTROLPROCESSFACILITY_H
#define SHAREMIND_ACCESSCONTROLPROCESSFACILITY_H

#include <cstddef>
#include <memory>
#include <sharemind/Concepts.h>
#include <sharemind/Range.h>
#include <sharemind/StringHashTablePredicate.h>
#include <string>
#include <type_traits>
#include <utility>


namespace sharemind {

/** \warning Please never convert this to an unscoped enumeration! Because
             values of unscoped enumerations may implicitly be converted to any
             integral type, such are not appropriate for use in access control.
*/
enum class AccessResult { Denied, Allowed, Unspecified };

class AccessControlProcessFacility {

public: /* Types: */

    using PreparedPredicateConcept = StringHashTablePredicate;

    SHAREMIND_DEFINE_CONCEPT(ValidArgument) {
        template <typename T>
        auto check(T && t) -> SHAREMIND_REQUIRE_CONCEPTS(
                        Callable(StringHasher const &, T &),
                        Any(DecaysTo(T, std::string),
                            ConvertibleTo(typename std::decay<T>::type,
                                          char const *),
                            InputRangeTo(T, char))
                    );
    };

protected: /* types: */

    struct PreparedPredicate {

        PreparedPredicate() noexcept {}
        PreparedPredicate(PreparedPredicate &&) noexcept = default;
        PreparedPredicate(PreparedPredicate const &) noexcept = default;

        virtual ~PreparedPredicate() noexcept {}

        PreparedPredicate & operator=(PreparedPredicate &&) noexcept = default;
        PreparedPredicate & operator=(PreparedPredicate const &) noexcept
                = default;

        virtual std::size_t hash() const noexcept = 0;
        virtual bool operator()(std::string const &) const = 0;

    };
    static_assert(Models<PreparedPredicateConcept(PreparedPredicate &)>::value,
                  "");

private: /* Types: */

    template <typename Pred>
    class PreparedPredicateImpl final: public PreparedPredicate {

    public: /* Methods: */

        template <typename ... Args>
        PreparedPredicateImpl(Args && ... args)
            : m_pred(std::forward<Args>(args)...)
        {}

        std::size_t hash() const noexcept final override
        { return m_pred.hash(); }

        virtual bool operator()(std::string const & str) const final override
        { return m_pred(str); }

    private: /* Fields: */

        Pred m_pred;

    };

public: /* Methods: */

    virtual ~AccessControlProcessFacility() noexcept {}

    AccessResult check() const noexcept { return AccessResult::Unspecified; }

    /**
        \brief Checks for access of the given rules.

        For each rule to check, the function takes two consecutive parameters,
        each of which is either models PreparedPredicateConcept, decays to a
        std::string, is convertible to (char const *) or is a range which can be
        compared to a std::string using sharemind::rangeEqual(). The first of
        each of these two is used to match the ruleset name, and the second is
        used to match the object (rule).

        \warning If comparing a given range with a std::string object using
                 rangeEqual() throws, AccessResult::Denied is returned.
        \warning Character arrays as arguments are considered to be ranges,
                 hence literal strings passed will contain the terminating NULL
                 character. Use sharemind::asLiteralStringRange("literal") as a
                 optimized workaround.
     */
    template <typename ... Args>
    auto check(Args && ... args) const noexcept
            -> typename std::enable_if<
                    (sizeof...(Args) > 0u) && ((sizeof...(Args) % 2u) == 0u)
                    && Models<ValidArgument(Args)...>::value,
                    AccessResult
                >::type
    { return checkWithPredicates_(getPredicate(std::forward<Args>(args))...); }

protected: /* Methods: */

    virtual AccessResult checkWithPredicates(
            PreparedPredicate const * const * ptrs,
            std::size_t size) const noexcept = 0;

private: /* Methods: */

    template <typename ... Args>
    AccessResult checkWithPredicates_(Args && ... args) const noexcept {
        PreparedPredicate const * const ptrs[] = { std::addressof(args)... };
        return checkWithPredicates(ptrs, sizeof...(Args) / 2u);
    }

    template <typename T,
              typename Base =
                    decltype(getOrCreateTemporaryStringHashTablePredicate(
                                std::declval<T &&>()))>
    static PreparedPredicateImpl<Base> getPredicate(T && t) {
        return PreparedPredicateImpl<Base>(
                    getOrCreateTemporaryStringHashTablePredicate(
                        std::forward<T>(t)));
    }

}; /* class AccessControlProcessFacility { */

} /* namespace sharemind */

#endif /* SHAREMIND_ACCESSCONTROLPROCESSFACILITY_H */
