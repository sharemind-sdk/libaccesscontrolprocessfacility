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
PROJECT(SharemindLibAccessControlProcessFacility VERSION 0.3.0 LANGUAGES "CXX")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers 1.6 REQUIRED)

FIND_PACKAGE(SharemindCxxHeaders 0.8.0 REQUIRED)


# LibAccessControlProcessFacility:
FILE(GLOB_RECURSE SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET(
    "include_SharemindLibAccessControlProcessFacility_headers_in_IDE"
    SOURCES ${SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS})
SharemindAddInterfaceLibrary(LibAccessControlProcessFacility)
TARGET_INCLUDE_DIRECTORIES(LibAccessControlProcessFacility
    INTERFACE
        # $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src> # TODO
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
    )
TARGET_LINK_LIBRARIES(LibAccessControlProcessFacility
        INTERFACE
            "Sharemind::CxxHeaders"
    )
INSTALL(FILES ${SHAREMIND_LIBACCESSCONTROLPROCESSFACILITY_HEADERS}
        DESTINATION "include/sharemind"
        COMPONENT "dev")
SharemindCreateCMakeFindFilesForTarget(LibAccessControlProcessFacility
    DEPENDENCIES
        "SharemindCxxHeaders 0.8.0"
)


# Tests:
SharemindSetCxx14CompileOptions()
SharemindAddSimpleTests("${CMAKE_CURRENT_SOURCE_DIR}/tests/Test*.cpp"
    LINK_LIBRARIES
        LibAccessControlProcessFacility
)


# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("dev"
    NAME "libsharemind-accesscontrolprocessfacility-api-dev"
    DESCRIPTION
        "Sharemind Access Control Process Facility API development headers"
    DEB_SECTION "libdevel"
    DEB_DEPENDS
        "libsharemind-cxxheaders-dev (>= 0.8.0)"
        "libstdc++-dev"
)
SharemindPackagingFinalize()
