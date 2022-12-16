/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2019-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#pragma once

#include <cstdint>
#include <string>

/// The code in this namespace is not intended to be called from outside
/// the `mongo::encryption` namespace
namespace mongo::encryption::detail {
/// @brief Reads an encryption key from the Vault server.
///
/// The address of the Vault server is specified via configuration file or
/// command line options.
///
/// @param secretPath path to the encryption key on the Vault server
/// @param secretVersion the version of the key;
///                      default is zero meaning the most recent version
///
/// @returns encryption key data in base64 encoded form
///
/// @throws std::runtime_error in case of issues
std::string vaultReadKey(const std::string& secretPath, std::uint64_t secretVersion = 0);

/// @brief Creates a copy of the key on the Vault server.
///
/// The address of the Vault server is specified via configuration file or
/// command line options.
///
/// The function never overwrites an existing entry on a Vault server,
/// it always creates a new one.
/// @todo Consider renaming to better reflect the latter fact.
///
/// @param secretPath path to the encryption key on the Vault server
/// @param key base64-encoded key data
///
/// @returns the version of created the key as a positive integer
///
/// @throws std::runtime_error in case of issues
std::uint64_t vaultWriteKey(const std::string& secretPath, std::string const& key);

}  // namespace mongo::encryption::detail
