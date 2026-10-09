//! OpenMLS crypto provider for `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87`.
//!
//! Wraps the libcrux provider (which already does ML-KEM-1024 HPKE, AES-256-GCM
//! and SHA-512) and adds ML-DSA-87 signatures. Every other suite is refused.

use khensu_crypto::{SigKeyPair, SigPublicKey};
use openmls_libcrux_crypto::CryptoProvider as LibcruxCrypto;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::storage::StorageProvider;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKeyPair, KemOutput, SignatureScheme,
};
use tls_codec::SecretVLBytes;

/// The only suite khensu.nu accepts (codepoint 0x0906).
pub const SUITE: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;

pub struct KhensuCrypto {
    inner: LibcruxCrypto,
}

impl KhensuCrypto {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self { inner: LibcruxCrypto::new()? })
    }
}

fn mldsa_only(alg: SignatureScheme) -> Result<(), CryptoError> {
    if alg == SignatureScheme::MLDSA87 { Ok(()) } else { Err(CryptoError::UnsupportedSignatureScheme) }
}

impl OpenMlsCrypto for KhensuCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == SUITE { Ok(()) } else { Err(CryptoError::UnsupportedCiphersuite) }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![SUITE]
    }

    fn hkdf_extract(&self, h: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(h, salt, ikm)
    }

    fn hmac(&self, h: HashType, key: &[u8], message: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(h, key, message)
    }

    fn hkdf_expand(
        &self,
        h: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(h, prk, info, okm_len)
    }

    fn hash(&self, h: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(h, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        mldsa_only(alg)?;
        let kp = SigKeyPair::generate().map_err(|_| CryptoError::InsufficientRandomness)?;
        Ok((kp.seed().to_vec(), kp.public().0.clone()))
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        mldsa_only(alg)?;
        SigPublicKey(pk.to_vec())
            .verify_raw(data, &[], signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        mldsa_only(alg)?;
        let seed: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let sig = SigKeyPair::from_seed(seed)
            .sign_raw(data, &[])
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(sig.0)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.inner
            .hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        self.inner.derive_hpke_keypair(config, ikm)
    }
}

impl OpenMlsRand for KhensuCrypto {
    type Error = <LibcruxCrypto as OpenMlsRand>::Error;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.inner.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.inner.random_vec(len)
    }
}

/// Provider with pluggable storage. The apps supply an encrypted SQLite store;
/// tests use memory.
pub struct KhensuProvider<S: StorageProvider<1> = MemoryStorage> {
    crypto: KhensuCrypto,
    storage: S,
}

impl KhensuProvider<MemoryStorage> {
    pub fn in_memory() -> Result<Self, CryptoError> {
        Ok(Self { crypto: KhensuCrypto::new()?, storage: MemoryStorage::default() })
    }
}

impl<S: StorageProvider<1>> KhensuProvider<S> {
    pub fn with_storage(storage: S) -> Result<Self, CryptoError> {
        Ok(Self { crypto: KhensuCrypto::new()?, storage })
    }
}

impl<S: StorageProvider<1>> OpenMlsProvider for KhensuProvider<S> {
    type CryptoProvider = KhensuCrypto;
    type RandProvider = KhensuCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &S {
        &self.storage
    }

    fn crypto(&self) -> &KhensuCrypto {
        &self.crypto
    }

    fn rand(&self) -> &KhensuCrypto {
        &self.crypto
    }
}

/// An MLS signature key for one device in one group.
pub struct MlDsaSigner {
    key: SigKeyPair,
}

impl MlDsaSigner {
    pub fn generate() -> Result<Self, khensu_crypto::Error> {
        Ok(Self { key: SigKeyPair::generate()? })
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: SigKeyPair::from_seed(seed) }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.key.public().0
    }

    pub(crate) fn key(&self) -> &SigKeyPair {
        &self.key
    }
}

impl Signer for MlDsaSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key.sign_raw(payload, &[]).map(|s| s.0).map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA87
    }
}
