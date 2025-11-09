////
/// Sparse Merkle Tree 
/// Universe: acts like a block explorer
/// A non-inclusion proof is the proof that the value at the unique position for a key is empty. 

#[derive(Debug)]
enum Node<T> {
    Branch,
    Leaf(T)
}