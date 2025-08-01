//! Trusted dealer
//!
//! Trusted dealer can be used to generate key shares in one place. Note
//! that it creates an SPOF/T (single point of failure/trust). Trusted
//! dealer is mainly intended to be used in tests.
//!
//! ## Example
//! Import a key into 3-out-of-5 TSS:
//! ```rust,no_run
//! # use rand_core::OsRng;
//! # let mut rng = OsRng;
//! use generic_ec::{curves::Secp256k1, SecretScalar, NonZero};
//!
//! let secret_key_to_be_imported = NonZero::<SecretScalar<Secp256k1>>::random(&mut rng);
//!
//! let key_shares = key_share::trusted_dealer::builder::<Secp256k1>(5)
//!     .set_threshold(Some(3))
//!     .set_shared_secret_key(secret_key_to_be_imported)
//!     .generate_shares(&mut rng)?;
//! # Ok::<_, key_share::trusted_dealer::TrustedDealerError>(())
//! ```

use alloc::vec::Vec;

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

use crate::{CoreKeyShare, VssSetup};

/// Construct a trusted dealer builder
///
/// Takes amount of key shares `n` to be generated
///
/// Alias to [`TrustedDealerBuilder::new`]
pub fn builder<E: Curve>(n: u16) -> TrustedDealerBuilder<E> {
    TrustedDealerBuilder::new(n)
}

/// Trusted dealer builder
pub struct TrustedDealerBuilder<E: Curve> {
    t: Option<u16>,
    n: u16,
    shared_secret_key: Option<NonZero<SecretScalar<E>>>,
    #[cfg(feature = "hd-wallet")]
    enable_hd: bool,
}

impl<E: Curve> TrustedDealerBuilder<E> {
    /// Construct a trusted dealer builder
    ///
    /// Takes amount of key shares `n` to be generated
    pub fn new(n: u16) -> Self {
        TrustedDealerBuilder {
            t: None,
            n,
            shared_secret_key: None,
            #[cfg(feature = "hd-wallet")]
            enable_hd: true,
        }
    }

    /// Sets threshold value
    ///
    /// If threshold is `Some(_)`, resulting key shares will be generated
    /// using t-out-of-n VSS scheme. If it's `None`, trusted dealer will
    /// generate additive key shares in n-out-ouf-n scheme.
    ///
    /// Note that setting `t=Some(n)` is not the same as setting `t=None`.
    /// Both produce n-out-of-n key shares, but `t=Some(n)` mocks threshold
    /// key generation with `threshold=n`, `t=None` mock non-threshold key
    /// generation.
    ///
    /// Default: `None`
    pub fn set_threshold(self, t: Option<u16>) -> Self {
        Self { t, ..self }
    }

    /// Sets shared secret key to be generated
    ///
    /// Resulting key shares will share specified secret key.
    pub fn set_shared_secret_key(self, sk: NonZero<SecretScalar<E>>) -> Self {
        Self {
            shared_secret_key: Some(sk),
            ..self
        }
    }

    /// Specifies that the key being generated shall support HD derivation
    #[cfg(feature = "hd-wallet")]
    pub fn hd_wallet(self, v: bool) -> Self {
        Self {
            enable_hd: v,
            ..self
        }
    }

    /// Generates [`CoreKeyShare`]s
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    ///
    /// For Shamir secret sharing, it's shared at points `1` to `n`
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_shares(
        self,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<CoreKeyShare<E>>, TrustedDealerError> {
        let key_shares_indexes = (1..=self.n)
            .map(|i| generic_ec::NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Reason::DeriveKeyShareIndex)?;
        self.generate_shares_at(key_shares_indexes, rng)
    }

    /// Generates [`CoreKeyShare`]s shared at random points
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    ///
    /// For Shamir secret sharing, the points at which the value is shared at
    /// are chosen at random between `1` and `u16::MAX`. For additive shares,
    /// this is the same as [`TrustedDealerBuilder::generate_shares`]
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_shares_at_random(
        self,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<CoreKeyShare<E>>, TrustedDealerError> {
        // The chance of scalars repeating is negligible for usual fields in EC.
        // But in any case the dupliactes are checked during the validation of
        // CoreKeyShare
        let points = (0..self.n)
            .map(|_| generic_ec::NonZero::<Scalar<E>>::random(rng))
            .collect();
        self.generate_shares_at(points, rng)
    }

    /// Generates [`CoreKeyShare`]s shared at preimages provided. Each share is
    /// going to have the given `preimages` as its `I` component.
    ///
    /// Preimages are ignored for additive key shares.
    ///
    /// Returns error if provided inputs are invalid, or if internal
    /// error has occurred.
    pub fn generate_shares_at(
        self,
        preimages: Vec<NonZero<Scalar<E>>>,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<CoreKeyShare<E>>, TrustedDealerError> {
        if preimages.len() != usize::from(self.n) {
            return Err(Reason::InvalidPreimages.into());
        }

        let shared_secret_key = self
            .shared_secret_key
            .unwrap_or_else(|| NonZero::<SecretScalar<_>>::random(rng));
        let shared_public_key = Point::generator() * &shared_secret_key;
        let secret_shares = if let Some(t) = self.t {
            let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
                rng,
                usize::from(t) - 1,
                shared_secret_key,
            );
            debug_assert_eq!(
                shared_public_key,
                Point::generator() * f.value::<_, Scalar<_>>(&Scalar::zero())
            );

            preimages
                .iter()
                .map(|I_i| f.value(I_i))
                .map(|mut x_i| SecretScalar::new(&mut x_i))
                .map(|x| NonZero::from_secret_scalar(x).ok_or(Reason::ZeroShare))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut shares = core::iter::repeat_with(|| NonZero::<SecretScalar<E>>::random(rng))
                .take((self.n - 1).into())
                .collect::<Vec<_>>();
            shares.push(
                NonZero::from_secret_scalar(SecretScalar::new(
                    &mut (shared_secret_key - shares.iter().sum::<SecretScalar<E>>()),
                ))
                .ok_or(Reason::ZeroShare)?,
            );
            debug_assert_eq!(
                shared_public_key,
                shares.iter().sum::<SecretScalar<E>>() * Point::generator()
            );
            shares
        };

        let public_shares = secret_shares
            .iter()
            .map(|s_i| Point::generator() * s_i)
            .collect::<Vec<_>>();

        let vss_setup = self.t.map(|t| VssSetup {
            min_signers: t,
            I: preimages,
        });

        #[cfg(feature = "hd-wallet")]
        let chain_code = if self.enable_hd {
            let mut code = hd_wallet::ChainCode::default();
            rng.fill_bytes(&mut code);
            Some(code)
        } else {
            None
        };

        Ok((0u16..)
            .zip(secret_shares)
            .map(|(i, x_i)| {
                crate::Validate::validate(crate::DirtyCoreKeyShare::<E> {
                    i,
                    key_info: crate::DirtyKeyInfo {
                        curve: Default::default(),
                        shared_public_key,
                        public_shares: public_shares.clone(),
                        vss_setup: vss_setup.clone(),
                        #[cfg(feature = "hd-wallet")]
                        chain_code,
                    },
                    x: x_i,
                })
                .map_err(|err| Reason::InvalidKeyShare(err.into_error()))
            })
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// Error explaining why trusted dealer failed to generate shares
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("trusted dealer failed to generate shares")]
pub struct TrustedDealerError(#[cfg_attr(feature = "std", source)] Reason);

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Reason {
    #[displaydoc("trusted dealer failed to generate shares due to internal error")]
    InvalidKeyShare(#[cfg_attr(feature = "std", source)] crate::InvalidCoreShare),
    #[displaydoc("deriving key share index failed")]
    DeriveKeyShareIndex,
    #[displaydoc("randomly generated share is zero - probability of that is negligible")]
    ZeroShare,
    #[displaydoc("invalid share preimages given")]
    InvalidPreimages,
}

impl From<Reason> for TrustedDealerError {
    fn from(err: Reason) -> Self {
        Self(err)
    }
}
