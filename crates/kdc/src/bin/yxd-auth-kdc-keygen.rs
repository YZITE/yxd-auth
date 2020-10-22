use yxd_auth_core::{base64::encode as b64encode, pdus, ring, ring::signature::KeyPair, Base64Key};

fn main() {
    let kp_noise = yz_encsess::generate_keypair(pdus::DHChoice::Ed25519).expect("unable to generate noise keypair");

    println!("# public noise key = {}", b64encode(&kp_noise.public));

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("unable to generate sign keypair");

    let kp_sign_dcd = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    println!("# public signing key = {}", b64encode(kp_sign_dcd.public_key()));

    let cfg = yxd_auth_kdc::ServerConfig {
        realm: "EXAMPLE.COM".to_string(),
        listen: "127.0.0.1:45949".parse().unwrap(),
        dbpath: std::path::PathBuf::from("/var/lib/yxd-auth/kdc.db"),
        privkey_noise: Base64Key(kp_noise.private),
        keypair_sign: Base64Key(pkcs8_bytes.as_ref().to_vec()),
    };

    println!("{}", toml::to_string(&cfg).expect("serialization failed"));
}
