use generic_ec::{Curve, Point};
use rand::{seq::SliceRandom, Rng, RngCore};
use rand_dev::DevRng;
use sha2::Sha256;

use cggmp21::{
    key_share::{AnyKeyShare, IncompleteKeyShare, KeyShare},
    ExecutionId,
};

cggmp21_tests::test_suite! {
    test: full_pipeline_works,
    generics: stark,
    suites: {
        t2n3: (2, 3, false),
        // t3n5: (3, 5, false),
        // #[cfg(feature = "hd-wallet")]
        // t3n5_hd: (3, 5, true),
    }
}
fn full_pipeline_works<E>(t: u16, n: u16, hd_enabled: bool)
where
    E: Curve + cggmp21_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{

    // here's where the private key is sharded. note that in this method, the original private key
    // is never `created` in the first place, which improves security, simply the shards are
    // created, and each shard is meant to help sign for the same shared_public_key (in eth, this
    // shared_public_key would be the eth address)
    let mut rng = DevRng::new();
    let incomplete_shares = run_keygen(t, n, hd_enabled, &mut rng);
    let shares = run_aux_gen(incomplete_shares, &mut rng);
    run_signing(&shares, hd_enabled, &mut rng);
}

fn run_keygen<E>(t: u16, n: u16, hd_enabled: bool, rng: &mut DevRng) -> Vec<IncompleteKeyShare<E>>
where
    E: Curve,
{
    #[cfg(not(feature = "hd-wallet"))]
    assert!(!hd_enabled);

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    round_based::sim::run(n, |i, party| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            let keygen = cggmp21::keygen(eid, i, n).set_threshold(t);

            #[cfg(feature = "hd-wallet")]
            let keygen = keygen.hd_wallet(hd_enabled);

            keygen.start(&mut party_rng, party).await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

fn run_aux_gen<E>(shares: Vec<IncompleteKeyShare<E>>, rng: &mut DevRng) -> Vec<KeyShare<E>>
where
    E: Curve,
{
    let mut primes = cggmp21_tests::CACHED_PRIMES.iter();
    let n = shares.len().try_into().unwrap();

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated_data = primes.next().expect("Can't fetch primes");
        async move {
            cggmp21::aux_info_gen(eid, i, n, pregenerated_data)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    shares
        .into_iter()
        .zip(aux_infos)
        .map(|(core, aux)| {
            KeyShare::from_parts((core, aux)).expect("Couldn't make share from parts")
        })
        .collect()
}

fn run_signing<E>(shares: &[KeyShare<E>], random_derivation_path: bool, rng: &mut DevRng)
where
    E: Curve + cggmp21_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    #[cfg(not(feature = "hd-wallet"))]
    assert!(!random_derivation_path);

    let t = shares[0].min_signers();
    let n = shares.len().try_into().unwrap();

    #[cfg(feature = "hd-wallet")]
    let derivation_path = if random_derivation_path {
        Some(cggmp21_tests::random_derivation_path(rng))
    } else {
        None
    };

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&original_message_to_sign);

    // Choose `t` signers to perform signing
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    // this is where the actual m of n signature is combined
    let sig = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        #[cfg(feature = "hd-wallet")]
        let derivation_path = derivation_path.clone();

        async move {
            let signing = cggmp21::signing(eid, i, participants, share);

            #[cfg(feature = "hd-wallet")]
            let signing = if let Some(derivation_path) = derivation_path {
                signing
                    .set_derivation_path_with_algo::<E::HdAlgo, _>(derivation_path)
                    .unwrap()
            } else {
                signing
            };

            signing.sign(&mut party_rng, party, message_to_sign).await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    #[cfg(feature = "hd-wallet")]
    let public_key = if let Some(path) = &derivation_path {
        generic_ec::NonZero::from_point(
            shares[0]
                .derive_child_public_key::<E::HdAlgo, _>(path.iter().cloned())
                .unwrap()
                .public_key,
        )
        .unwrap()
    } else {
        shares[0].shared_public_key
    };
    #[cfg(not(feature = "hd-wallet"))]
    let public_key = shares[0].shared_public_key;

    // SIG is the signature generated by m of n signers 
    // public_key is `equivalent` to the eth address 
    // this fn below verifies that the signature was created for this message by this public key
    // (by this eth address, basically)
    // eth is compatible with secp256k1 signing, that this lib supports
    // NOTE that we still have to modify this lib to make it work with eth
    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");
}
