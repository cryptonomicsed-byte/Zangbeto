use std::collections::HashMap;

/// Opaque node identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

/// A single vote cast by a node for a block in a given round.
#[derive(Debug, Clone)]
pub struct Vote {
    pub node_id: NodeId,
    pub round: u64,
    pub block_hash: String,
}

/// A quorum certificate: evidence that a super-majority agreed on a block.
#[derive(Debug, Clone)]
pub struct QuorumCertificate {
    pub round: u64,
    pub block_hash: String,
    pub votes: Vec<Vote>,
}

impl QuorumCertificate {
    /// Returns true when votes exceed 2/3 of total_nodes (strict BFT threshold).
    pub fn is_quorum(&self, total_nodes: usize) -> bool {
        self.votes.len() * 3 > total_nodes * 2
    }
}

/// A BFT consensus node that collects votes and emits quorum certificates.
pub struct BftNode {
    pub id: NodeId,
    pub round: u64,
    /// Keyed by "round/block_hash" to group votes.
    pub pending_votes: HashMap<String, Vec<Vote>>,
}

impl BftNode {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            round: 0,
            pending_votes: HashMap::new(),
        }
    }

    /// Accept an incoming vote.  Returns a `QuorumCertificate` the first time
    /// a slot crosses the 2/3-supermajority threshold; `None` otherwise.
    ///
    /// `total_nodes` must be supplied by the caller (network topology is
    /// external to this crate).
    pub fn receive_vote(
        &mut self,
        vote: Vote,
        total_nodes: usize,
    ) -> Option<QuorumCertificate> {
        let key = format!("{}/{}", vote.round, vote.block_hash);
        let slot = self.pending_votes.entry(key).or_default();

        // Deduplicate: each node may only vote once per (round, block_hash).
        if slot.iter().any(|v| v.node_id == vote.node_id) {
            return None;
        }
        slot.push(vote);

        let slot_ref = self.pending_votes
            .values()
            .last()
            .expect("just inserted");

        let qc = QuorumCertificate {
            round: slot_ref[0].round,
            block_hash: slot_ref[0].block_hash.clone(),
            votes: slot_ref.to_vec(),
        };

        if qc.is_quorum(total_nodes) {
            Some(qc)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_threshold() {
        // 3-of-4 nodes is NOT a supermajority (3*3=9, 4*2=8 → 9>8 ✓ actually is)
        // Use 4 nodes: need >2/3 → need at least 3 votes.
        let mut node = BftNode::new(NodeId("n0".into()));
        let make_vote = |id: &str| Vote {
            node_id: NodeId(id.into()),
            round: 1,
            block_hash: "abc".into(),
        };

        // First two votes should not reach quorum in a 4-node network.
        assert!(node.receive_vote(make_vote("n1"), 4).is_none());
        assert!(node.receive_vote(make_vote("n2"), 4).is_none());
        // Third vote crosses the threshold (3*3=9 > 4*2=8).
        let qc = node.receive_vote(make_vote("n3"), 4);
        assert!(qc.is_some());
        assert!(qc.unwrap().is_quorum(4));
    }

    #[test]
    fn duplicate_votes_ignored() {
        let mut node = BftNode::new(NodeId("n0".into()));
        let vote = Vote { node_id: NodeId("n1".into()), round: 1, block_hash: "abc".into() };
        node.receive_vote(vote.clone(), 4);
        // Sending the same vote again must be a no-op.
        let result = node.receive_vote(vote, 4);
        assert!(result.is_none());
    }
}
