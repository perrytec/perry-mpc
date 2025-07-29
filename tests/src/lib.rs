use anyhow::{bail, Context, Result};
use cggmp21::{key_share::KeyShare, rug::Integer, security_level::SecurityLevel};
use generic_ec::Curve;
use rand::RngCore;
use serde_json::{Map, Value};

/// Wraps a sink to buffer the messages. Used in [`buffer_outgoing`]
#[pin_project::pin_project]
pub struct BufferedSink<M, Inner> {
    #[pin]
    messages: std::collections::VecDeque<M>,
    #[pin]
    inner: Inner,
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Always ready to buffer
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Feed all buffered messages one by one
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            // In case the inner sink wasn't ready, this method will be retried.
            // We rely on this and don't modify any internal state before this
            // point
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Modified 'Delivery' of the party to buffer outgoing messages. The messages
/// fed to the 'Delivery' sink will be buffered indefinitely until `flush` is
/// called
///
/// This is useful since the delivery used in round-based simulation doesn't do
/// buffering at all, however we want to verify that we don't forget to flush
/// the messages in our protocols. When this function is used, forgetting to
/// flush will cause the test to get stuck.
pub fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink::<round_based::Outgoing<M>, D::Send> {
            messages: std::collections::VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}

pub mod external_verifier;

lazy_static::lazy_static! {
    pub static ref CACHED_SHARES: PrecomputedKeyShares =
        PrecomputedKeyShares::from_serialized(
            include_str!("../../test-data/precomputed_shares.json")
        ).unwrap();
    pub static ref CACHED_PRIMES: PregeneratedPrimes =
        PregeneratedPrimes::from_serialized(
            include_str!("../../test-data/pregenerated_primes.json")
        ).unwrap();
}

pub struct PrecomputedKeyShares {
    shares: Map<String, Value>,
}

impl PrecomputedKeyShares {
    pub fn empty() -> Self {
        Self {
            shares: Default::default(),
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_serialized(shares: &str) -> Result<Self> {
        let shares = serde_json::from_str(shares).context("parse shares")?;
        Ok(Self { shares })
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.shares).context("serialize shares")
    }

    pub fn get_shares<E: Curve, L: SecurityLevel>(
        &self,
        t: Option<u16>,
        n: u16,
        hd_enabled: bool,
    ) -> Result<Vec<KeyShare<E, L>>> {
        let key_shares = self
            .shares
            .get(&Self::key::<E>(t, n, hd_enabled))
            .context("shares not found")?;
        serde_json::from_value(key_shares.clone()).context("parse key shares")
    }

    pub fn add_shares<E: Curve, L: SecurityLevel>(
        &mut self,
        t: Option<u16>,
        n: u16,
        hd_enabled: bool,
        shares: &[KeyShare<E, L>],
    ) -> Result<()> {
        if usize::from(n) != shares.len() {
            bail!("expected {n} key shares, only {} provided", shares.len());
        }
        let key_shares = serde_json::to_value(shares).context("serialize shares")?;
        self.shares
            .insert(Self::key::<E>(t, n, hd_enabled), key_shares);
        Ok(())
    }

    fn key<E: Curve>(t: Option<u16>, n: u16, hd_enabled: bool) -> String {
        format!(
            "t={t:?},n={n},curve={},hd_wallet={hd_enabled}",
            E::CURVE_NAME
        )
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes {
    // It would be better to use key_refresh::PregeneratedPrimes here, but
    // adding serialization to that is an enormous pain in the ass
    primes: Vec<Integer>,
    bitsize: u32,
}

impl PregeneratedPrimes {
    pub fn from_serialized(repr: &str) -> Result<Self> {
        serde_json::from_str(repr).context("parse primes")
    }

    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize primes")
    }

    /// Iterate over numbers, producing pregenerated pairs for key refresh
    pub fn iter<L>(&self) -> impl Iterator<Item = cggmp21::key_refresh::PregeneratedPrimes<L>> + '_
    where
        L: cggmp21::security_level::SecurityLevel,
    {
        if self.bitsize != 4 * L::SECURITY_BITS {
            panic!("Attempting to use generated primes while expecting wrong bit size");
        }
        self.primes.chunks(2).map(|s| {
            let p = &s[0];
            let q = &s[1];
            cggmp21::key_refresh::PregeneratedPrimes::new(p.clone(), q.clone())
                .expect("primes have wrong bit size")
        })
    }

    /// Generate enough primes so that you can do `amount` of key refreshes
    pub fn generate<R, L>(amount: usize, rng: &mut R) -> Self
    where
        L: cggmp21::security_level::SecurityLevel,
        R: RngCore,
    {
        let bitsize = 4 * L::SECURITY_BITS;
        let primes = (0..amount)
            .flat_map(|_| {
                let p = generate_blum_prime(rng, bitsize);
                let q = generate_blum_prime(rng, bitsize);
                [p, q]
            })
            .collect();

        Self { primes, bitsize }
    }
}

/// Generates a blum prime
///
/// CGGMP21 requires using safe primes, however blum primes do not break correctness of the protocol
/// and they can be generated faster.
///
/// Only to be used in the tests.
pub fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> Integer {
    loop {
        let mut n: Integer = Integer::random_bits(
            bits_size,
            &mut cggmp21::fast_paillier::utils::external_rand(rng),
        )
        .into();
        n.set_bit(bits_size - 1, true);
        n.next_prime_mut();
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

pub fn convert_stark_scalar(
    x: &generic_ec::Scalar<cggmp21::supported_curves::Stark>,
) -> anyhow::Result<starknet_crypto::FieldElement> {
    let bytes = x.to_be_bytes();
    debug_assert_eq!(bytes.len(), 32);
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(bytes.as_bytes());
    starknet_crypto::FieldElement::from_bytes_be(&buffer)
        .map_err(|e| anyhow::Error::msg(format!("Can't convert scalar: {}", e)))
}

pub fn convert_from_stark_scalar(
    x: &starknet_crypto::FieldElement,
) -> anyhow::Result<generic_ec::Scalar<generic_ec::curves::Stark>> {
    let bytes = x.to_bytes_be();
    generic_ec::Scalar::from_be_bytes(bytes).context("Can't read bytes")
}

#[cfg(feature = "hd-wallet")]
pub fn random_derivation_path(rng: &mut impl rand::RngCore) -> Vec<u32> {
    use rand::Rng;
    let len = rng.gen_range(1..=3);
    std::iter::repeat_with(|| rng.gen_range(0..cggmp21::hd_wallet::H))
        .take(len)
        .collect::<Vec<_>>()
}

/// Parameters per each curve that are needed in tests
pub trait CurveParams: Curve {
    /// Which HD derivation algorithm to use with that curve
    #[cfg(feature = "hd-wallet")]
    type HdAlgo: cggmp21::hd_wallet::HdWallet<Self>;
    /// External verifier for signatures on this curve
    type ExVerifier: external_verifier::ExternalVerifier<Self>;
}

impl CurveParams for cggmp21::supported_curves::Secp256k1 {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp21::hd_wallet::Slip10;
    type ExVerifier = external_verifier::blockchains::Bitcoin;
}

impl CurveParams for cggmp21::supported_curves::Secp256r1 {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp21::hd_wallet::Slip10;
    type ExVerifier = external_verifier::Noop;
}

impl CurveParams for cggmp21::supported_curves::Stark {
    #[cfg(feature = "hd-wallet")]
    type HdAlgo = cggmp21::hd_wallet::Stark;
    type ExVerifier = external_verifier::blockchains::StarkNet;
}

#[macro_export]
macro_rules! test_suite {
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: stark,
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        $crate::test_suite! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                secp256k1: <cggmp21::supported_curves::Secp256k1>,
                secp256r1: <cggmp21::supported_curves::Secp256r1>,
                stark: <cggmp21::supported_curves::Stark>,
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: {$($gmod:ident: <$($generic:path),*>),+$(,)?},
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        mod $($test)? $($async_test)? {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: {$($gmod: <$($generic),+>),+},
                suites: {$($suites)*}
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! test_suite_traverse {
    (
        // Either `$async_test` or `$test` must be present, but not at the same time
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // we traverse over `generics`
        generics: {
            $gmod:ident: <$($generic:path),*>
            $(, $($generics_rest:tt)*)?
        },
        suites: {$($suites:tt)*}
    ) => {
        mod $gmod {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: <$($generic),+>,
                suites: {$($suites)*}
            }
        }
        $crate::test_suite_traverse! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                $($($generics_rest)*)?
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // generics list is empty - nothing to traverse
        generics: {},
        suites: {$($suites:tt)*}
    ) => {};

    (
        async_test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse async suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[tokio::test]
        async fn $suite_name() {
            $test::<$($generic),+>($($args)*).await
        }

        $crate::test_suite_traverse! {
            async_test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse sync suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[test]
        fn $suite_name() {
            $test::<$($generic),+>($($args)*)
        }

        $crate::test_suite_traverse! {
            test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: <$($generic:path),*>,
        // suites list is empty - nothing to traverse
        suites: {}
    ) => {};
}
