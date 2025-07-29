use generic_ec::Point;
use rand::seq::SliceRandom;
use rand::Rng;
use sha2::Sha256;

use cggmp21::{
    key_share::{DirtyKeyShare, Validate},
    security_level::SecurityLevel128,
    ExecutionId,
};

cggmp21_tests::test_suite! {
    test: key_refresh_works,
    generics: all_curves,
    suites: {
        n3: (3, false),
        n5: (5, false),
        n5_reliable: (5, true),
    }
}
fn key_refresh_works<E: generic_ec::Curve>(n: u16, reliable_broadcast: bool)
where
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    let shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(None, n, true)
        .expect("retrieve cached shares");

    #[cfg(feature = "hd-wallet")]
    assert!(shares[0].chain_code.is_some());

    let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<SecurityLevel128>();

    // Perform refresh

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let key_shares = round_based::sim::run_with_setup(&shares, |_i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated_data = primes.next().expect("Can't fetch primes");
        async move {
            cggmp21::key_refresh(eid, share, pregenerated_data)
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // validate key shares

    for (i, key_share) in key_shares.iter().enumerate() {
        let i = i as u16;
        assert_eq!(i, key_share.core.i);
        assert_eq!(
            key_share.core.shared_public_key,
            key_shares[0].core.shared_public_key
        );
        assert_eq!(
            key_share.core.public_shares,
            key_shares[0].core.public_shares
        );
        assert_eq!(
            Point::<E>::generator() * &key_share.core.x,
            key_share.core.public_shares[usize::from(i)]
        );
    }
    assert_eq!(
        key_shares[0].core.shared_public_key,
        key_shares[0].core.public_shares.iter().sum::<Point<E>>()
    );
    for key_share in &key_shares {
        assert_eq!(
            key_share.core.shared_public_key,
            shares[0].core.shared_public_key
        );
    }

    #[cfg(feature = "hd-wallet")]
    for key_share in &key_shares {
        assert_eq!(key_share.chain_code, shares[0].chain_code);
    }

    // attempt to sign with new shares and verify the signature

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);
    let participants = &(0..n).collect::<Vec<_>>();
    let sig = round_based::sim::run_with_setup(&key_shares, |_i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            cggmp21::signing(eid, share.core.i, participants, share)
                .enforce_reliable_broadcast(reliable_broadcast)
                .sign(&mut party_rng, party, message_to_sign)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    sig.verify(&key_shares[0].core.shared_public_key, &message_to_sign)
        .expect("signature is not valid");
}

cggmp21_tests::test_suite! {
    test: aux_gen_works,
    generics: all_curves,
    suites: {
        t2n3: (2, 3, false),
        t3n5: (3, 5, false),
        t3n5_reliable: (3, 5, true),
    }
}
fn aux_gen_works<E: generic_ec::Curve>(t: u16, n: u16, reliable_broadcast: bool)
where
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    let shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(Some(t), n, false)
        .expect("retrieve cached shares");
    let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<SecurityLevel128>();

    // Perform refresh

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let aux_infos = round_based::sim::run(n, |i, party| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let pregenerated_data = primes.next().expect("Can't fetch primes");
        async move {
            cggmp21::aux_info_gen(eid, i, n, pregenerated_data)
                .enforce_reliable_broadcast(reliable_broadcast)
                .start(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // validate key shares

    let key_shares = shares
        .into_iter()
        .zip(aux_infos)
        .map(|(share, aux)| {
            DirtyKeyShare {
                core: share.into_inner().core,
                aux: aux.into_inner(),
            }
            .validate()
            .unwrap()
        })
        .collect::<Vec<_>>();

    // attempt to sign with new shares and verify the signature

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);

    // choose t participants
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &key_shares[usize::from(*i)]);

    let sig = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        async move {
            cggmp21::signing(eid, i, participants, share)
                .enforce_reliable_broadcast(reliable_broadcast)
                .sign(&mut party_rng, party, message_to_sign)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    sig.verify(&key_shares[0].core.shared_public_key, &message_to_sign)
        .expect("signature is not valid");
}
