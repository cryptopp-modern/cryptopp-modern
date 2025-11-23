// config.h - originally written and placed in the public domain by Wei Dai

/// \file config.h
/// \brief Library configuration file
/// \details <tt>config.h</tt> was split into components in May 2019 to better
///  integrate with Autoconf and its feature tests. The splitting occurred so
///  users could continue to include <tt>config.h</tt> while allowing Autoconf
///  to write new <tt>config_asm.h</tt> and new <tt>config_cxx.h</tt> using
///  its feature tests.
/// \sa <A HREF="https://github.com/weidai11/cryptopp/issues/835">Issue 835,
///  Make config.h more autoconf friendly</A>,
///  <A HREF="https://www.cryptopp.com/wiki/Configure.sh">Configure.sh script</A>
///  on the Crypto++ wiki
/// \since Crypto++ 8.3

/// \file config.h
/// \brief Library configuration file

#ifndef CRYPTOPP_CONFIG_H
#define CRYPTOPP_CONFIG_H

#include <cryptopp/config_align.h>
#include <cryptopp/config_asm.h>
#include <cryptopp/config_cpu.h>
#include <cryptopp/config_cxx.h>
#include <cryptopp/config_dll.h>
#include <cryptopp/config_int.h>
#include <cryptopp/config_misc.h>
#include <cryptopp/config_ns.h>
#include <cryptopp/config_os.h>
#include <cryptopp/config_ver.h>

#endif // CRYPTOPP_CONFIG_H
