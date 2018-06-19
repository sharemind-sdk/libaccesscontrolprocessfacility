#
# Copyright (C) Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION "3.0")
PROJECT(SharemindLibAccessControlProcessFacility VERSION "0.1.0" LANGUAGES "CXX")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.2 REQUIRED)

SharemindSetProjectVersion()


FIND_PACKAGE(SharemindCxxHeaders REQUIRED)

FILE(GLOB_RECURSE SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET(
    "include_SharemindLibAccessControlProcessFacility_headers_in_IDE"
    SOURCES ${SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS})

INSTALL(FILES ${SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS}
        DESTINATION "include/sharemind"
        COMPONENT "api-dev")


# Install cmake files:
SharemindCreateCMakeFindFiles(
    COMPONENT "api-dev"
    DEFINITIONS
        ${SharemindCxxHeaders_DEFINITIONS}
    INCLUDE_DIRS
        "${CMAKE_INSTALL_PREFIX}/include"
        ${SharemindCxxHeaders_INCLUDE_DIRS}
    LIBRARIES
        ${SharemindCxxHeaders_LINK_LIBRARIES}
)


# Tests:
SharemindSetCxx11CompileOptions()
SharemindAddSimpleTests("${CMAKE_CURRENT_SOURCE_DIR}/tests/Test*.cpp"
    LEGACY_DEFINITIONS
        ${SharemindCxxHeaders_DEFINITIONS}
    INCLUDE_DIRECTORIES
        ${SharemindCxxHeaders_INCLUDE_DIRS}
    LINK_LIBRARIES
        ${SharemindCxxHeaders_LINK_LIBRARIES}
    LINK_FLAGS
        "-Wl,-rpath=${CMAKE_CURRENT_BINARY_DIR}/"
)


# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("api-dev"
    NAME "libsharemind-accesscontrolprocessfacility-api-dev"
    DESCRIPTION
        "Sharemind Access Control Process Facility API development headers"
    DEB_SECTION "libdevel"
    DEB_DEPENDS
        "libsharemind-cxxheaders-dev (>= 0.1.0)"
        "libstdc++-dev"
)
SharemindPackagingFinalize()
