use std::{fmt::Display, str::FromStr};

use bitcoin::{hashes::{Hash, HashEngine, sha256}, hex::{DisplayHex, FromHex}};

/// Represents the key of a MS-SMT
/// A key in a MS-SMT 256 bit since our hash function used here is sha256
#[derive(Clone)]
pub struct NodeHash(pub [u8; 32]);

impl NodeHash {
    pub fn new(b: [u8; 32]) -> Self {
        NodeHash(b)
    }
}

impl Default for NodeHash {
    fn default() -> Self {
        NodeHash([0; 32])
    }
}

impl FromStr for NodeHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err("Invalid string length".to_string());
        }
        let res = <[u8; 32]>::from_hex(s).map_err(|e| format!("Hex to array error {:?}", e))?;

        Ok(NodeHash(res))
    }
}

impl Display for NodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.as_hex().to_string())
    }
}

pub trait Node {
    fn sum(&self) -> u64;
    fn value(&self) -> [u8; 32];
    fn hash(&self) -> NodeHash;
}

#[allow(dead_code)]
pub struct LeafNode {
    value: [u8; 32],
    sum: u64,
    hash: Option<NodeHash>,
}

impl LeafNode {
    pub fn is_empty(&self) -> bool {
        self.value.len() == 0 && self.sum == 0
    }
}


impl Node for LeafNode {

    fn sum(&self) -> u64 {
        self.sum
    }

    fn value(&self) -> [u8; 32] {
        self.value
    }

    /// The node digest which is a function of sum encoded as big endian and the leaf value
    fn hash(&self) -> NodeHash {
        if self.hash.is_some() {
            return self.hash.as_ref().unwrap().clone();
        }

        let mut hash_engine = sha256::HashEngine::default();

        hash_engine.input(&self.value);
        hash_engine.input(&self.sum.to_be_bytes());

        let res = sha256::Hash::from_engine(hash_engine);

        
        NodeHash(res.to_byte_array())
    }
}


#[allow(dead_code)]
pub struct BranchNode {
    left: Box<dyn Node>,
    right: Box<dyn Node>,

    hash: Option<NodeHash>,
    sum: u64,
}

/// @TODO mutable reference to update and cache the values
impl Node for BranchNode {

    fn sum(&self) -> u64 {
        self.left.sum() + self.right.sum()
    }

    fn value(&self) -> [u8; 32] {
        [0; 32]
    }

    fn hash(&self) -> NodeHash {
        if self.hash.is_some() {
            return self.hash.as_ref().unwrap().clone();
        }

        let left_hash = self.left.hash();
        let right_hash = self.right.hash();

        let mut hash_engine = sha256::HashEngine::default();

        hash_engine.input(&left_hash.0);
        hash_engine.input(&right_hash.0);
        hash_engine.input(&self.sum.to_be_bytes());

        let res = sha256::Hash::from_engine(hash_engine);

        NodeHash(res.to_byte_array())
    }
}

#[allow(dead_code)]
pub enum NodeKind {
    BranchNode(BranchNode),
    LeafNode(LeafNode),
}

impl BranchNode {
    pub fn new(left: Box<dyn Node>, right: Box<dyn Node>) -> Self {
        Self {
            left,
            right,
            hash: Some(NodeHash::default()),
            sum: 0,
        }
    }
}

#[allow(dead_code)]
pub struct ComputedNode {
    hash: NodeHash,
    sum: u64
}

impl ComputedNode {
    pub fn new(hash: NodeHash, sum: u64) -> Self {
        Self { hash, sum }
    }
}