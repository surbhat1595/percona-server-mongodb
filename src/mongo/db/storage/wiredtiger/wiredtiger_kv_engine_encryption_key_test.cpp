/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2022-present Percona and/or its affiliates. All rights reserved.

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


#include <cstdint>
#include <memory>
#include <optional>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_id.h"
#include "mongo/db/encryption/key_operations.h"
#include "mongo/db/encryption/master_key_provider.h"
#include "mongo/db/service_context_test_fixture.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/logv2/log_component.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/clock_source_mock.h"
#include "mongo/util/invariant.h"

namespace mongo {
namespace {
using namespace encryption;
class FakeReadVaultSecret : public ReadKey {
public:
    explicit FakeReadVaultSecret(const VaultSecretId& id) : _id(id) {}
    std::optional<Key> operator()() const override {
        return Key("9Ccgjp8dCj1zwb1yv56hFcF1uEA30IRFiMml7EhzUVk=");
    }
    const KeyId& keyId() const noexcept {
        return _id;
    }

private:
    VaultSecretId _id;
};

class FakeSaveVaultSecret : public SaveKey {
public:
    explicit FakeSaveVaultSecret(const std::string& secretPath)
        : _secretPath(secretPath),
          _secretVersion(0) {}
    std::unique_ptr<KeyId> operator()(const Key& key) const override {
        return std::make_unique<VaultSecretId>(_secretPath, ++_secretVersion);
    }
    const char* facilityType() const noexcept {
        return "FAKE VAULT SERVER";
    }

private:
    std::string _secretPath;
    mutable std::uint64_t _secretVersion;
};

class FakeVaultSecretOperationFactory : public VaultSecretOperationFactory {
public:
    FakeVaultSecretOperationFactory(
        bool rotateMasterKey,
        const std::string& providedSecretPath,
        const std::optional<std::uint64_t>& providedSecretVersion)
        : VaultSecretOperationFactory(rotateMasterKey, providedSecretPath, providedSecretVersion) {}

private:
    std::unique_ptr<ReadKey> _doCreateRead(const VaultSecretId& id) const override {
        return std::make_unique<FakeReadVaultSecret>(id);
    }
    std::unique_ptr<SaveKey> _doCreateSave(const std::string& secretPath) const override {
        return std::make_unique<FakeSaveVaultSecret>(secretPath);
    }
};

std::unique_ptr<KeyOperationFactory> createFakeKeyOperationFactory(
    const EncryptionGlobalParams& params) {
    if (!params.vaultServerName.empty()) {
        return std::make_unique<FakeVaultSecretOperationFactory>(
            params.vaultRotateMasterKey, params.vaultSecret, params.vaultSecretVersion);
    }
    invariant(false && "Should not reach this point");
    return nullptr;
}

std::unique_ptr<MasterKeyProvider> createFakeMasterKeyProvider(
    const EncryptionGlobalParams& params, const logv2::LogComponent logComponent) {
    return std::make_unique<MasterKeyProvider>(
        createFakeKeyOperationFactory(params), WtKeyIds::instance(), logComponent);
}

std::string toJsonText(const KeyId& id) {
    BSONObjBuilder b;
    id.serialize(&b);
    return b.obj().jsonString();
}

struct WiredTigerKVEngineEncryptionKeyTest : ServiceContextTest {};

TEST_F(WiredTigerKVEngineEncryptionKeyTest, Stub) {
    encryptionGlobalParams.enableEncryption = true;
    encryptionGlobalParams.vaultServerName = "nonsense";
    encryptionGlobalParams.vaultPort = 1;
    encryptionGlobalParams.vaultToken = "nonsese";
    encryptionGlobalParams.vaultSecret = "alpha/bravo";
    encryptionGlobalParams.vaultSecretVersion = 4242;

    unittest::TempDir dbpath("wt_kv_key");
    std::unique_ptr<ClockSource> cs = std::make_unique<ClockSourceMock>();

    auto kv = std::make_unique<WiredTigerKVEngine>(
        "wiredTiger",
        dbpath.path(),
        cs.get(),
        "log=(file_max=1m,prealloc=false)",
        1,
        1,
        true,
        false,
        false,
        false,
        createFakeMasterKeyProvider);
    kv->notifyStartupComplete();

    ASSERT(WtKeyIds::instance().futureConfigured);
    ASSERT_EQUALS(toJsonText(*WtKeyIds::instance().futureConfigured),
                  R"json({"vaultSecretIdentifier":{"path":"alpha/bravo","version":"4242"}})json");
}
}  // namespace
}  // namespace mongo
