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
#include <sharemind/SimpleUnorderedStringMap.h>
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

    /// Mapping from object names to Allow/Deny:
    class ObjectPermissions: public SimpleUnorderedStringMap<AccessResult> {

    public: /* Methods: */

        AccessResult checkAccess() const noexcept
        { return AccessResult::Unspecified; }

        template <typename ... ObjectNamePredicates>
        auto checkAccess(ObjectNamePredicates && ... objectNamePredicates)
                const
                -> SHAREMIND_REQUIRE_CONCEPTS_R(
                        AccessResult,
                        StringHashTablePredicate(ObjectNamePredicates &)...
                    )
        {
            if (empty())
                return AccessResult::Unspecified;
            return checkAccess_(std::forward<ObjectNamePredicates>(
                                    objectNamePredicates)...);
        }

    private: /* Methods: */

        template <typename ObjectNamePredicate>
        AccessResult checkAccess_(ObjectNamePredicate && objectNamePredicate)
                const
        {
            assert(!empty());
            auto const it(find(std::forward<ObjectNamePredicate>(
                                   objectNamePredicate)));
            return (it != end()) ? it->second : AccessResult::Unspecified;
        }

        template <typename ObjectNamePredicate, typename ... Args>
        AccessResult checkAccess_(ObjectNamePredicate && objectNamePredicate,
                                  Args && ... args) const
        {
            assert(!empty());
            {
                auto const r(checkAccess_(std::forward<ObjectNamePredicate>(
                                              objectNamePredicate)));
                switch (r) {
                case AccessResult::Denied:
                    return r;
                case AccessResult::Unspecified:
                    return checkAccess_(std::forward<Args>(args)...);
                case AccessResult::Allowed:
                    break;
                }
            }
            auto const r(checkAccess_(std::forward<Args>(args)...));
            return (r == AccessResult::Unspecified) ? AccessResult::Allowed : r;
        }

    };

    SHAREMIND_DEFINE_CONCEPT(ValidArgument) {
        template <typename T>
        auto check(T && t)
                -> decltype(getOrCreateTemporaryStringHashTablePredicate(
                                std::forward<T>(t)));
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

        virtual std::size_t hash() const = 0;
        virtual bool operator()(std::string const &) const = 0;

    };
    static_assert(Models<StringHashTablePredicate(PreparedPredicate &)>::value,
                  "");

private: /* Types: */

    template <typename Pred>
    class PreparedPredicateImpl final: public PreparedPredicate {

    public: /* Methods: */

        template <typename ... Args>
        PreparedPredicateImpl(Args && ... args)
            : m_pred(std::forward<Args>(args)...)
        {}

        std::size_t hash() const final override
        { return m_pred.hash(); }

        virtual bool operator()(std::string const & str) const final override
        { return m_pred(str); }

    private: /* Fields: */

        Pred m_pred;

    };

public: /* Methods: */

    virtual ~AccessControlProcessFacility() noexcept {}

    /**
      \brief Short-circuit for access checking when no object names are given.
      \param rulesetNamePredicate not used
      \returns AccessResult::Unspecified
    */
    template <typename RulesetNamePredicate>
    constexpr auto check(RulesetNamePredicate && rulesetNamePredicate)
            const noexcept
            -> SHAREMIND_REQUIRE_CONCEPTS_R(AccessResult,
                                            ValidArgument(RulesetNamePredicate))
    {
        (void) rulesetNamePredicate;
        return AccessResult::Unspecified;
    }

    /**
        \brief Checks for access under a given ruleset and set of objects.

        \param rulesetNamePredicate A ruleset name predicate (or something
                                    convertible to it) which is used to match
                                    the ruleset under which rules are to be
                                    checked.
        \param objectNamePredicates Object name predicates (or objects
                                    convertible to such) which are used to match
                                    the object names under the given ruleset.

        \warning Does not throw exceptions unless exceptions are thrown by the
                 operations on the passed hash table predicates (or hash table
                 predicates constructed from the arguments), for example when
                 comparing a given range with a std::string object using
                 sharemind::rangeEqual() throws.
        \warning Character arrays as arguments are considered to be ranges,
                 hence literal strings passed will contain the terminating NULL
                 character. Use sharemind::asLiteralStringRange("literal") as a
                 optimized workaround.
     */
    template <typename RulesetNamePredicate, typename ... ObjectNamePredicates>
    auto check(RulesetNamePredicate && rulesetNamePredicate,
               ObjectNamePredicates && ... objectNamePredicates) const
            -> SHAREMIND_REQUIRE_CONCEPTS_R(
                    AccessResult,
                    ValidArgument(RulesetNamePredicate),
                    ValidArgument(ObjectNamePredicates)...
                )
    {
        if (auto const perms =
                    currentPermissions(
                        getPredicate(std::forward<RulesetNamePredicate>(
                                         rulesetNamePredicate))))
            return perms->checkAccess(
                        getPredicate(std::forward<ObjectNamePredicates>(
                                         objectNamePredicates))...);
        return AccessResult::Unspecified;
    }

    template <typename RulesetNamePredicate>
    auto currentPermissions(RulesetNamePredicate && rulesetNamePredicate) const
            -> SHAREMIND_REQUIRE_CONCEPTS_R(
                    std::shared_ptr<ObjectPermissions const>,
                    ValidArgument(RulesetNamePredicate)
                )
    {
        return getCurrentPermissions(
                    getPredicate(std::forward<RulesetNamePredicate>(
                                     rulesetNamePredicate)));
    }

protected: /* Methods: */

    virtual std::shared_ptr<ObjectPermissions const> getCurrentPermissions(
            PreparedPredicate const & rulesetNamePredicate) const = 0;

private: /* Methods: */

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
