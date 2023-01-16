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
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "mongo/db/encryption/encryption_options.h"
#include "mongo/db/encryption/key.h"
#include "mongo/db/encryption/key_id.h"
#include "mongo/db/encryption/key_operations.h"
#include "mongo/db/encryption/master_key_provider.h"
#include "mongo/db/service_context_test_fixture.h"
#include "mongo/db/storage/master_key_rotation_completed.h"
#include "mongo/db/storage/wiredtiger/wiredtiger_kv_engine.h"
#include "mongo/logv2/log_component.h"
#include "mongo/unittest/death_test.h"
#include "mongo/unittest/temp_dir.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/assert_util_core.h"
#include "mongo/util/clock_source_mock.h"

namespace mongo {
namespace {
using namespace encryption;

std::ostream& operator<<(std::ostream& os, const Key& key) {
    os << key.base64();
    return os;
}

EncryptionGlobalParams encryptionParamsKeyFile(const std::string& keyFilePath) {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.encryptionKeyFile = keyFilePath;
    return params;
}

EncryptionGlobalParams encryptionParamsVault(
    const std::string& secretPath = "", std::optional<std::uint64_t> secretVersion = std::nullopt) {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.vaultServerName = "vault.com";
    params.vaultPort = 1;
    params.vaultToken = "nonsese";
    if (!secretPath.empty()) {
        params.vaultSecret = secretPath;
        if (secretVersion) {
            params.vaultSecretVersion = secretVersion;
        }
    }
    return params;
}

EncryptionGlobalParams encryptionParamsKmip(const std::string& keyId = "") {
    EncryptionGlobalParams params;
    params.enableEncryption = true;
    params.kmipServerName = "kmip.com";
    params.kmipPort = 1;
    if (!keyId.empty()) {
        params.kmipKeyIdentifier = keyId;
    }
    return params;
}

std::unique_ptr<WiredTigerKVEngine> createWiredTigerKVEngine(
    const std::string& dbpath,
    ClockSource* cs,
    const MasterKeyProviderFactory& keyProviderFactory) {
    auto engine = std::make_unique<WiredTigerKVEngine>("wiredTiger",
                                                       dbpath,
                                                       cs,
                                                       "log=(file_max=1m,prealloc=false)",
                                                       1,
                                                       1,
                                                       true,
                                                       false,
                                                       false,
                                                       false,
                                                       keyProviderFactory);
    engine->notifyStartupComplete();
    return engine;
}

class FakeVaultServer {
public:
    std::optional<Key> readKey(const VaultSecretId& id) const noexcept {
        auto engine = _keys.find(id.path());
        if (engine == _keys.end() || engine->second.empty() ||
            engine->second.size() < id.version()) {
            return std::nullopt;
        }
        if (id.version() == 0) {
            return *engine->second.rbegin();
        }
        return engine->second.at(id.version() - 1);
    }

    VaultSecretId saveKey(const std::string& path, const Key& key) {
        auto& v = _keys[path];
        v.push_back(key);
        return VaultSecretId(path, v.size());
    }

    void clear() noexcept {
        _keys.clear();
    }

private:
    std::map<std::string, std::vector<Key>> _keys;
};

class FakeReadVaultSecret : public ReadVaultSecret {
public:
    explicit FakeReadVaultSecret(FakeVaultServer& server, const VaultSecretId& id)
        : ReadVaultSecret(id), _server(server) {}

    std::optional<Key> operator()() const override {
        return _server.readKey(vaultSecretId());
    }

private:
    FakeVaultServer& _server;
};

class FakeSaveVaultSecret : public SaveVaultSecret {
public:
    explicit FakeSaveVaultSecret(FakeVaultServer& server, const std::string& secretPath)
        : SaveVaultSecret(secretPath), _server(server) {}

    std::unique_ptr<KeyId> operator()(const Key& key) const override {
        return std::make_unique<VaultSecretId>(_server.saveKey(secretPath(), key));
    }

private:
    FakeVaultServer& _server;
};

class FakeVaultSecretOperationFactory : public VaultSecretOperationFactory {
public:
    FakeVaultSecretOperationFactory(FakeVaultServer& server,
                                    bool rotateMasterKey,
                                    const std::string& providedSecretPath,
                                    const std::optional<std::uint64_t>& providedSecretVersion)
        : VaultSecretOperationFactory(rotateMasterKey, providedSecretPath, providedSecretVersion),
          _server(server) {}

private:
    std::unique_ptr<ReadKey> _doCreateRead(const VaultSecretId& id) const override {
        return std::make_unique<FakeReadVaultSecret>(_server, id);
    }

    std::unique_ptr<SaveKey> _doCreateSave(const std::string& secretPath) const override {
        return std::make_unique<FakeSaveVaultSecret>(_server, secretPath);
    }

    FakeVaultServer& _server;
};

class FakeKmipServer {
public:
    std::optional<Key> readKey(const KmipKeyId& id) const {
        std::size_t i = std::stoull(id.toString());
        invariant(i > 0);
        return _keys.at(i - 1);
    }

    KmipKeyId saveKey(const Key& key) {
        _keys.push_back(key);
        return KmipKeyId(std::to_string(_keys.size()));
    }

    void clear() noexcept {
        _keys.clear();
    }

private:
    std::vector<Key> _keys;
};

class FakeReadKmipKey : public ReadKmipKey {
public:
    FakeReadKmipKey(FakeKmipServer& server, const KmipKeyId& id)
        : ReadKmipKey(id), _server(server) {}

    std::optional<Key> operator()() const override {
        return _server.readKey(kmipKeyId());
    }

private:
    FakeKmipServer& _server;
};

class FakeSaveKmipKey : public SaveKmipKey {
public:
    FakeSaveKmipKey(FakeKmipServer& server) : _server(server) {}

    std::unique_ptr<KeyId> operator()(const Key& key) const override {
        return std::make_unique<KmipKeyId>(_server.saveKey(key));
    }

private:
    FakeKmipServer& _server;
};

class FakeKmipKeyOperationFactory : public KmipKeyOperationFactory {
public:
    FakeKmipKeyOperationFactory(FakeKmipServer& server,
                                bool rotateMasterKey,
                                const std::string& providedKeyId)
        : KmipKeyOperationFactory(rotateMasterKey, providedKeyId), _server(server) {}

private:
    std::unique_ptr<ReadKey> _doCreateRead(const KmipKeyId& id) const override {
        return std::make_unique<FakeReadKmipKey>(_server, id);
    }
    std::unique_ptr<SaveKey> _doCreateSave() const override {
        return std::make_unique<FakeSaveKmipKey>(_server);
    }

    FakeKmipServer& _server;
};

class FakeMasterKeyProviderFactory {
public:
    FakeMasterKeyProviderFactory(FakeVaultServer& vaultServer, FakeKmipServer& kmipServer)
        : _vaultServer(vaultServer), _kmipServer(kmipServer) {}

    std::unique_ptr<MasterKeyProvider> operator()(const EncryptionGlobalParams& params,
                                                  const logv2::LogComponent logComponent) {
        return std::make_unique<MasterKeyProvider>(
            createFakeKeyOperationFactory(_vaultServer, _kmipServer, params),
            WtKeyIds::instance(),
            logComponent);
    }

private:
    static std::unique_ptr<KeyOperationFactory> createFakeKeyOperationFactory(
        FakeVaultServer& vaultServer,
        FakeKmipServer& kmipServer,
        const EncryptionGlobalParams& params) {
        if (!params.encryptionKeyFile.empty()) {
            return std::make_unique<KeyFileOperationFactory>(params.encryptionKeyFile);
        } else if (!params.vaultServerName.empty()) {
            return std::make_unique<FakeVaultSecretOperationFactory>(vaultServer,
                                                                     params.vaultRotateMasterKey,
                                                                     params.vaultSecret,
                                                                     params.vaultSecretVersion);
        } else if (!params.kmipServerName.empty()) {
            return std::make_unique<FakeKmipKeyOperationFactory>(
                kmipServer, params.kmipRotateMasterKey, params.kmipKeyIdentifier);
        }
        invariant(false && "Should not reach this point");
        return nullptr;
    }

    FakeVaultServer& _vaultServer;
    FakeKmipServer& _kmipServer;
};


std::string toJsonText(const KeyId& id) {
    BSONObjBuilder b;
    id.serialize(&b);
    return b.obj().jsonString();
}

class WiredTigerKVEngineEncryptionKeyVaultTest : public ServiceContextTest {
public:
    WiredTigerKVEngineEncryptionKeyVaultTest() {}

    void setUp() override {
        _vaultServer.saveKey("charlie/delta", Key());
        _vaultServer.saveKey("charlie/delta", Key());
        encryptionGlobalParams = encryptionParamsVault("charlie/delta");
        _tempDir = std::make_unique<unittest::TempDir>("wt_kv_key");
        _clockSource = std::make_unique<ClockSourceMock>();
        _engine = _createWiredTigerKVEngine();
        WtKeyIds::instance().configured = std::move(WtKeyIds::instance().futureConfigured);
        _engine.reset();
    }

    void tearDown() override {
        _engine.reset();
        _clockSource.reset();
        _tempDir.reset();
        WtKeyIds::instance().configured.reset();
        WtKeyIds::instance().decryption.reset();
        WtKeyIds::instance().futureConfigured.reset();
        encryptionGlobalParams = EncryptionGlobalParams();
        _vaultServer.clear();
        _kmipServer.clear();
    }

protected:
    std::unique_ptr<WiredTigerKVEngine> _createWiredTigerKVEngine() {
        return createWiredTigerKVEngine(_tempDir->path(),
                                        _clockSource.get(),
                                        FakeMasterKeyProviderFactory(_vaultServer, _kmipServer));
    }

    FakeVaultServer _vaultServer;
    FakeKmipServer _kmipServer;
    std::unique_ptr<unittest::TempDir> _tempDir;
    std::unique_ptr<ClockSource> _clockSource;
    std::unique_ptr<WiredTigerKVEngine> _engine;
};

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, EncryptionKeyFileIsUsedIfItIsInParams) {
    Key key = *_vaultServer.readKey(VaultSecretId("charlie/delta", 3));
    // Make sure the engine won't read the key from the Vault server
    _vaultServer.clear();

    std::string path = _tempDir->path() + "/encryption_key.txt";
    std::ofstream f(path);
    if (f) {
        f << key.base64();
    } else {
        FAIL("Can't create the encryption key file");
    }
    f.close();
    namespace fs = std::filesystem;
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);

    encryptionGlobalParams = encryptionParamsKeyFile(path);
    _engine = _createWiredTigerKVEngine();

    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), key);
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(KeyFilePath(path)));
}

DEATH_TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
             DeathIfKmipInParams,
             "Trying to decrypt the data-at-rest with the key from a KMIP server "
             "but the system was configured with a key from a Vault server.") {
    Key key = *_vaultServer.readKey(VaultSecretId("charlie/delta", 3));
    KmipKeyId kmipKeyId = _kmipServer.saveKey(key);
    encryptionGlobalParams = encryptionParamsKmip(kmipKeyId.toString());

    _engine = _createWiredTigerKVEngine();
}

/// @brief Verify that the engine uses specific Vault secret
///
/// @param id identifier of the expected Vault secret
#define ASSERT_KEY_ID(id)                                                             \
    _engine = _createWiredTigerKVEngine();                                            \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id)); \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));


TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ConfiguredSecretIdIsUsedIfNoSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault();
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       ConfiguredSecretIdIsUsedIfNoSecretVersionInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest, ConfiguredSecretIdIsUsedIfSameSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 3);
    ASSERT_KEY_ID(VaultSecretId("charlie/delta", 3));
}

#undef ASSERT_KEY_ID

DEATH_TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
             DeathIfDifferentSecretVersionInParams,
             "Vault secret identifier is not equal to that the system is already configured with") {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 1);
    _engine = _createWiredTigerKVEngine();
}

DEATH_TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
             DeathIfDifferentSecretPathInParams,
             "Vault secret identifier is not equal to that the system is already configured with") {
    encryptionGlobalParams = encryptionParamsVault("foo/bar", 3);
    _engine = _createWiredTigerKVEngine();
}

DEATH_TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
             DeathIfDifferentSecretPathWithoutVersionInParams,
             "Vault secret path is not equal to that the system is already configured with") {
    encryptionGlobalParams = encryptionParamsVault("foo/bar");
    _engine = _createWiredTigerKVEngine();
}

/// @brief Verify that master key rotation completes successfully and
/// the engine uses new master key (i.e. Vault secret)
///
/// @param id identifier of the expected Vault secret
#define ASSERT_ROTATION_NEW_KEY_ID(id)                                                  \
    ASSERT_THROWS(_createWiredTigerKVEngine(), MasterKeyRotationCompleted);             \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().futureConfigured), toJsonText(id));      \
                                                                                        \
    WtKeyIds::instance().configured = std::move(WtKeyIds::instance().futureConfigured); \
    encryptionGlobalParams = encryptionParamsVault();                                   \
    _engine = _createWiredTigerKVEngine();                                              \
    ASSERT_EQ(_engine->getEncryptionKeyDB()->masterKey(), *_vaultServer.readKey(id));   \
    ASSERT_EQ(toJsonText(*WtKeyIds::instance().decryption), toJsonText(id));


TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesConfiguredSecretPathIfNoSecretIdInParams) {
    encryptionGlobalParams = encryptionParamsVault();
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 4));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesConfiguredSecretPathIfSameSecretPathInParams) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta");
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 4));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretIdIfItsSecretPathIsSameToConfigured) {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 1);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("charlie/delta", 1));
}

DEATH_TEST_REGEX_F(WiredTigerKVEngineEncryptionKeyVaultTest,
                   RotationDeathIfProvidedSecretIdEqualToConfigured,
                   "rotation.*but the provided.*key identifier is equal to.*configured") {
    encryptionGlobalParams = encryptionParamsVault("charlie/delta", 3);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    _engine = _createWiredTigerKVEngine();
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretPathIfItDiffersFromConfigured) {
    encryptionGlobalParams = encryptionParamsVault("foxtrot/golf");
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("foxtrot/golf", 1));
}

TEST_F(WiredTigerKVEngineEncryptionKeyVaultTest,
       RotationUsesProvidedSecretIdIfItDiffersFromConfigured) {
    _vaultServer.saveKey("kilo/lima", Key());
    _vaultServer.saveKey("kilo/lima", Key());

    encryptionGlobalParams = encryptionParamsVault("kilo/lima", 2);
    encryptionGlobalParams.vaultRotateMasterKey = true;

    ASSERT_ROTATION_NEW_KEY_ID(VaultSecretId("kilo/lima", 2));
}

#undef ASSERT_ROTATION_NEW_KEY_ID

}  // namespace
}  // namespace mongo
