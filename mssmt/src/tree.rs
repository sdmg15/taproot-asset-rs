use std::{fmt::Display, str::FromStr};

use bitcoin::{hashes::{Hash, HashEngine, sha256}, hex::{DisplayHex, FromHex}};

pub const MAX_TREE_LEVEL: usize = 256;
pub const LAST_BIT_INDEX: usize = MAX_TREE_LEVEL - 1;

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

#[derive(Clone)]
struct BranchNode {
    left: Box<Node>,
    right: Box<Node>,
    hash: Option<NodeHash>,
    sum: u64,
}

impl BranchNode {
    pub fn new(left: Node, right: Node) -> Self {
        BranchNode { left: Box::new(left), right: Box::new(right), hash: None, sum: 0 }
    }
}

#[derive(Clone)]
struct LeafNode {
    value: [u8; 32],
    sum: u64,
    hash: Option<NodeHash>,
}

impl Default for LeafNode {
    fn default() -> Self {
        LeafNode { value: [0; 32], sum: 0, hash: None }
    }
}

#[derive(Clone)]
#[allow(dead_code)]

enum Node {
    Branch(BranchNode),
    Leaf(LeafNode),

    ComputedNode {
        hash: NodeHash,
        sum: u64
    },

    Nil,
}

impl Node {

    fn hash(&mut self) -> NodeHash {

        match self  {
            Self::Branch (bn) => {

                if bn.hash.is_some() {
                    return bn.hash.as_ref().unwrap().clone();
                }

                let left_hash = bn.left.hash();
                let right_hash = bn.right.hash();

                let mut hash_engine = sha256::HashEngine::default();

                hash_engine.input(&left_hash.0);
                hash_engine.input(&right_hash.0);
                hash_engine.input(&bn.sum.to_be_bytes());

                let res = sha256::Hash::from_engine(hash_engine);
                bn.hash = Some(NodeHash(res.to_byte_array()));

                bn.hash.as_ref().unwrap().clone()
            },

            Self::Leaf (ln) => {

                if ln.hash.is_some() {
                    return ln.hash.as_ref().unwrap().clone();
                }

                let mut hash_engine = sha256::HashEngine::default();
                hash_engine.input(&ln.value);
                hash_engine.input(&ln.sum.to_be_bytes());

                let res = sha256::Hash::from_engine(hash_engine);
                ln.hash = Some(NodeHash(res.to_byte_array()));

                ln.hash.as_ref().unwrap().clone()
            },

            Self::ComputedNode { hash, .. } => {
                hash.clone()
            },

            Self::Nil => NodeHash::default(),
        }
    }


    pub fn sum(&self) -> u64 {
        
        match self {
            Self::Branch(bn) => {
                bn.left.sum() + bn.right.sum()
            },

            Self::Leaf(ln) => {
                ln.sum
            },

            Self::ComputedNode { .. } => 0,
            Self::Nil => 0,
        }
    }
}

#[allow(dead_code)]
pub struct Tree {
    tree: Vec<Node>,
    root_hash: NodeHash
}

impl Tree {

    pub fn init() -> Tree {

        let mut tree_levels: Vec<Node> = Vec::with_capacity(MAX_TREE_LEVEL + 1);

        tree_levels[MAX_TREE_LEVEL] = Node::Leaf(LeafNode::default());

        (0..LAST_BIT_INDEX).rev().for_each(|idx| {

            let branch = BranchNode::new(
                tree_levels[idx + 1].clone(),
                tree_levels[idx + 1].clone()
            );

            tree_levels[idx] = Node::Branch(branch);
        });

        Tree { 
            root_hash: tree_levels[0].hash(),
            tree: tree_levels, 
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tree::Tree;

    fn new_tree() {
        let _ms_tree = Tree::init();
    }
}