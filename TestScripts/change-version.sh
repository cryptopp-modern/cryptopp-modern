#!/usr/bin/env bash

#############################################################################
#
# This script updates the Crypto++ version to calendar versioning.
# Usage: ./change-version.sh YEAR MONTH [INCREMENT]
#
# Example: ./change-version.sh 2025 11 0
#
# Written and placed in public domain by Jeffrey Walton and Colin Brown.
#
# Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2)
# licensed under the Boost Software License 1.0, while the individual files
# in the compilation are all public domain.
#
# See https://www.cryptopp.com/wiki/Release_Versioning for more details
#
#############################################################################

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 YEAR MONTH [INCREMENT]"
    echo "Example: $0 2025 11 0"
    exit 1
fi

YEAR=$1
MONTH=$2
INCREMENT=${3:-0}

# Validation
if [ "$YEAR" -lt 2025 ] || [ "$YEAR" -gt 2099 ]; then
    echo "Error: Year must be between 2025 and 2099"
    exit 1
fi

if [ "$MONTH" -lt 1 ] || [ "$MONTH" -gt 12 ]; then
    echo "Error: Month must be between 1 and 12"
    exit 1
fi

if [ "$INCREMENT" -lt 0 ] || [ "$INCREMENT" -gt 99 ]; then
    echo "Error: Increment must be between 0 and 99"
    exit 1
fi

# Calculate CRYPTOPP_VERSION
VERSION=$((YEAR * 10000 + MONTH * 100 + INCREMENT))

echo "Updating to version ${YEAR}.${MONTH}.${INCREMENT} (CRYPTOPP_VERSION=${VERSION})"

# Update config_ver.h
echo "Updating config_ver.h..."
sed -i.bak \
    -e "s/^#define CRYPTOPP_MAJOR [0-9]*/#define CRYPTOPP_MAJOR ${YEAR}/" \
    -e "s/^#define CRYPTOPP_MINOR [0-9]*/#define CRYPTOPP_MINOR ${MONTH}/" \
    -e "s/^#define CRYPTOPP_REVISION [0-9]*/#define CRYPTOPP_REVISION ${INCREMENT}/" \
    -e "s/^#define CRYPTOPP_VERSION [0-9]*/#define CRYPTOPP_VERSION ${VERSION}/" \
    config_ver.h

# Update Doxyfile
echo "Updating Doxyfile..."
sed -i.bak \
    -e "s/^PROJECT_NUMBER[[:space:]]*=.*/PROJECT_NUMBER         = ${YEAR}.${MONTH}/" \
    Doxyfile

# Verify changes
echo ""
echo "Verification:"
grep "^#define CRYPTOPP_" config_ver.h | grep -E "MAJOR|MINOR|REVISION|VERSION"
grep "^PROJECT_NUMBER" Doxyfile

echo ""
echo "Version update complete!"
echo "Please review changes before committing."
