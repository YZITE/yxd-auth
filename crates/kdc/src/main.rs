use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct ServerConfig {
    listen: String,
    
}

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yxd-auth-kdc CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: ServerConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");



    println!("Hello, world!");
}
