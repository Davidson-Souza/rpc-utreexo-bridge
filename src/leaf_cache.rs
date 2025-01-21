use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::OutPoint;
use kv::Batch;
use kv::Config;
use log::info;

use crate::prover::LeafCache;
use crate::udata::LeafContext;

pub struct DiskLeafStorage {
    /// In-memory cache of leaf data
    ///
    /// This is used to avoid hitting the disk database too often,
    /// we put things here until it reaches a certain size, then we
    /// flush it to disk.
    /// If we die before flushing, we'll need txindex to rebuild the
    /// cache.
    cache: HashMap<OutPoint, (u32, LeafContext)>,
    /// A disk database of leaf data
    ///
    /// This is used to store leaf data that is not in the cache,
    /// it's a simple kv bucket with no fancy features.
    bucket: kv::Bucket<'static, Vec<u8>, Vec<u8>>,
}

impl LeafCache for DiskLeafStorage {
    fn insert(&mut self, outpoint: OutPoint, leaf_data: LeafContext) -> bool {
        self.cache
            .insert(outpoint, (leaf_data.block_height, leaf_data));
        self.cache.len() > 100_000
    }

    fn get(&self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.cache
            .get(outpoint)
            .map(|(_, leaf_data)| leaf_data.clone())
            .or_else(|| {
                let leaf = self.bucket.get(&serialize(outpoint)).ok().flatten()?;
                let block_height = deserialize(&leaf[0..4]).unwrap();
                let txid = deserialize(&leaf[4..36]).unwrap();
                let vout = deserialize(&leaf[36..40]).unwrap();
                let value = deserialize(&leaf[40..48]).unwrap();
                let block_hash = deserialize(&leaf[48..80]).unwrap();
                let is_coinbase = deserialize(&leaf[80..81]).unwrap();
                let median_time_past = deserialize(&leaf[81..85]).unwrap();
                let pk_script = deserialize(&leaf[85..]).unwrap();

                Some(LeafContext {
                    block_height,
                    txid,
                    vout,
                    value,
                    pk_script,
                    block_hash,
                    is_coinbase,
                    median_time_past,
                })
            })
    }

    fn remove(&mut self, outpoint: &OutPoint) -> Option<LeafContext> {
        self.cache
            .remove(outpoint)
            .map(|(_, leaf_data)| leaf_data)
            .or_else(|| {
                let leaf = self.bucket.remove(&serialize(outpoint)).ok().flatten()?;
                let block_height = deserialize(&leaf[0..4]).unwrap();
                let txid = deserialize(&leaf[4..36]).unwrap();
                let vout = deserialize(&leaf[36..40]).unwrap();
                let value = deserialize(&leaf[40..48]).unwrap();
                let block_hash = deserialize(&leaf[48..80]).unwrap();
                let is_coinbase = deserialize(&leaf[80..81]).unwrap();
                let median_time_past = deserialize(&leaf[81..85]).unwrap();
                let pk_script = deserialize(&leaf[85..]).unwrap();

                Some(LeafContext {
                    block_height,
                    txid,
                    vout,
                    value,
                    pk_script,
                    block_hash,
                    is_coinbase,
                    median_time_past,
                })
            })
    }

    fn flush(&mut self) {
        self.flush();
    }

    fn cache_size(&self) -> usize {
        self.cache_size()
    }
}

impl DiskLeafStorage {
    pub fn new(dir: &str) -> Self {
        let db = kv::Store::new(Config {
            cache_capacity: Some(1_000_000),
            path: dir.into(),
            flush_every_ms: Some(100),
            segment_size: None,
            temporary: false,
            use_compression: false,
        })
        .expect("Failed to open leaf cache database");
        let bucket = db.bucket::<Vec<u8>, Vec<u8>>(None).unwrap();
        Self {
            bucket,
            cache: HashMap::with_capacity(100_000),
        }
    }

    fn cache_size(&self) -> usize {
        self.cache.len()
    }

    fn serialize_leaf_data(leaf_data: &LeafContext) -> Vec<u8> {
        let mut serialized = serialize(&leaf_data.block_height);
        serialized.extend_from_slice(&serialize(&leaf_data.txid));
        serialized.extend_from_slice(&serialize(&leaf_data.vout));
        serialized.extend_from_slice(&serialize(&leaf_data.value));
        serialized.extend_from_slice(&serialize(&leaf_data.block_hash));
        serialized.extend_from_slice(&serialize(&leaf_data.is_coinbase));
        serialized.extend_from_slice(&serialize(&leaf_data.median_time_past));
        serialized.extend_from_slice(&serialize(&leaf_data.pk_script));
        serialized
    }

    fn flush(&mut self) {
        info!("Flushing leaf cache to disk, this might take a while");
        let mut new_map = HashMap::new();
        let mut batch = Batch::new();
        for (outpoint, (height, leaf_data)) in self.cache.iter() {
            // Don't uncache things that are too recent
            if *height < 100 {
                new_map.insert(*outpoint, (*height, leaf_data.clone()));
            }

            let serialized = Self::serialize_leaf_data(leaf_data);
            batch
                .set(&serialize(outpoint), &serialized)
                .expect("Failed to flush leaf cache");
        }
        info!("Applying batch to disk, this might take a while");
        self.bucket
            .batch(batch)
            .expect("Failed to flush leaf cache");

        self.cache = new_map;
    }
}
