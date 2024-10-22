use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use actix_rt::signal::ctrl_c;
use log::info;
use log::warn;

use crate::block_index::BlocksIndex;
use crate::chainview;
use crate::get_chain_provider;
use crate::init_logger;
use crate::prover;
use crate::shinigami_block_storage::JsonBlockFiles;
use crate::subdir;

pub fn run_bridge() -> anyhow::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .create(subdir(""))
        .unwrap();

    // Initialize the logger
    init_logger(
        Some(&subdir("debug.log")),
        simplelog::LevelFilter::Info,
        true,
    );

    // to keep track of the current chain state and speed up replying to headers requests
    // from peers.
    let store = kv::Store::new(kv::Config {
        path: subdir("chain_view").into(),
        temporary: false,
        use_compression: false,
        flush_every_ms: None,
        cache_capacity: None,
        segment_size: None,
    })
    .expect("Failed to open chainview database");

    // Chainview is a collection of metadata about the chain, like tip and block
    // indexes. It's stored in a key-value database.
    let view = chainview::ChainView::new(store);
    let view = Arc::new(view);

    // This database stores some useful information about the blocks, but not
    // the blocks themselves
    let index_store = BlocksIndex {
        database: kv::Store::new(kv::Config {
            path: subdir("index/").into(),
            temporary: false,
            use_compression: false,
            flush_every_ms: Some(1000),
            cache_capacity: Some(1_000_000),
            segment_size: None,
        })
        .unwrap(),
    };

    // Put it into an Arc so we can share it between threads
    let index_store = Arc::new(index_store);

    // This database stores the blocks themselves, it's a collection of flat files
    // that are indexed by the index above. They are stored in the `blocks/` directory
    // and are serialized as bitcoin blocks, so we don't need to do any parsing
    // before sending to a peer.
    let blocks = Arc::new(RwLock::new(JsonBlockFiles::new(subdir("blocks/").into())));

    // The prover needs some way to pull blocks from a trusted source, we can use anything
    // implementing the [Blockchain] trait, for example a bitcoin core node or an esplora
    // instance.
    let client = get_chain_provider()?;

    // Create a prover, this module will download blocks from the bitcoin core
    // node and save them to disk. It will also create proofs for the blocks
    // and save them to disk.
    let leaf_data = HashMap::new();
    let mut prover = prover::Prover::new(client, index_store, blocks, view, leaf_data);

    info!("Starting p2p node");

    let kill_signal = Arc::new(Mutex::new(false));
    let kill_signal2 = kill_signal.clone();

    // Keep the prover running in the background, it will download blocks and
    // create proofs for them as they are mined.
    info!("Running prover");
    std::thread::spawn(move || {
        actix_rt::System::new().block_on(async {
            let _ = ctrl_c().await;
            warn!("Received a stop signal");
            *kill_signal.lock().unwrap() = true;
        })
    });

    prover.keep_up(kill_signal2)
}