use std::{collections::HashMap, sync::Arc};

use bdk_bitcoind_rpc::{BlockEvent, MempoolEvent};
use bdk_chain::{
    CanonicalizationParams, CheckPoint, ConfirmationBlockTime, FullTxOut, IndexedTxGraph, Merge,
    bitcoin::{
        Block, BlockHash, Network, ScriptBuf, Transaction,
        key::Secp256k1,
        secp256k1::{All, SecretKey},
    },
    indexed_tx_graph,
    local_chain::{self, LocalChain},
    miniscript::Descriptor,
    spk_txout::SpkTxOutIndex,
};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChangeSet {
    indexed_graph: indexed_tx_graph::ChangeSet<ConfirmationBlockTime, ()>,
    local_chain: local_chain::ChangeSet,
    network: Option<Network>,
}

impl Default for ChangeSet {
    fn default() -> Self {
        Self {
            indexed_graph: Default::default(),
            local_chain: Default::default(),
            network: None,
        }
    }
}

impl Merge for ChangeSet {
    fn merge(&mut self, other: Self) {
        self.indexed_graph.merge(other.indexed_graph);
        self.local_chain.merge(other.local_chain);
        if other.network.is_some() {
            self.network = other.network;
        }
    }

    fn is_empty(&self) -> bool {
        self.indexed_graph.is_empty() && self.local_chain.is_empty() && self.network.is_none()
    }
}

impl From<local_chain::ChangeSet> for ChangeSet {
    fn from(local_chain: local_chain::ChangeSet) -> Self {
        Self {
            local_chain,
            ..Default::default()
        }
    }
}

impl From<indexed_tx_graph::ChangeSet<ConfirmationBlockTime, ()>> for ChangeSet {
    fn from(indexed_graph: indexed_tx_graph::ChangeSet<ConfirmationBlockTime, ()>) -> Self {
        Self {
            indexed_graph,
            ..Default::default()
        }
    }
}

pub struct SpkTracker {
    graph: IndexedTxGraph<ConfirmationBlockTime, SpkTxOutIndex<ScriptBuf>>,
    chain: LocalChain,
    stage: ChangeSet,
    secrets: HashMap<ScriptBuf, SecretKey>,
    network: Network,
    secp: Secp256k1<All>,
}

impl SpkTracker {
    pub fn new(network: Network, genesis_hash: BlockHash) -> Self {
        let mut stage = ChangeSet::default();
        let graph = IndexedTxGraph::<ConfirmationBlockTime, SpkTxOutIndex<ScriptBuf>>::default();
        let (chain, changeset) = LocalChain::from_genesis_hash(genesis_hash);
        stage.merge(changeset.into());
        Self {
            graph,
            chain,
            stage,
            secrets: Default::default(),
            network,
            secp: Secp256k1::new(),
        }
    }

    pub fn from_changeset(changeset: ChangeSet) -> anyhow::Result<Self> {
        let mut stage = ChangeSet::default();
        let (graph, graph_changeset) =
            IndexedTxGraph::<ConfirmationBlockTime, SpkTxOutIndex<ScriptBuf>>::from_changeset(
                changeset.indexed_graph,
                |_| anyhow::Ok(SpkTxOutIndex::<ScriptBuf>::default()),
            )?;
        stage.merge(graph_changeset.into());
        let chain = LocalChain::from_changeset(changeset.local_chain)?;
        Ok(Self {
            graph,
            chain,
            stage,
            secrets: Default::default(),
            network: changeset.network.ok_or(anyhow::anyhow!("no network"))?,
            secp: Secp256k1::new(),
        })
    }

    /// Take from the staged changes.
    ///
    /// For persistence.
    pub fn take_stage(&mut self) -> ChangeSet {
        core::mem::take(&mut self.stage)
    }

    /// Reindex.
    ///
    /// Incase an spk was added after a relevant transaction was already synced.
    pub fn reindex(&mut self) -> bool {
        let changeset = self.graph.reindex();
        let has_changes = !changeset.is_empty();
        self.stage.merge(changeset.into());
        has_changes
    }
}

/// Methods for managing secrets, UTXOs.
impl SpkTracker {
    /// Add a secret.
    ///
    /// Secrets are not persisted.
    ///
    /// Remember to call [`reindex`](SpkTracker::reindex) if secret is added after a relevant
    /// transaction is already seen by the `SpkTracker`.
    pub fn add_secret(&mut self, secret: SecretKey) -> anyhow::Result<bool> {
        let (pk, _) = secret.x_only_public_key(&self.secp);
        let spk = Descriptor::new_tr(pk, None)?.script_pubkey();
        if self.graph.index.insert_spk(spk.clone(), spk.clone()) {
            self.secrets.insert(spk, secret);
            return Ok(true);
        }
        Ok(false)
    }

    pub fn secrets_by_spk(&self) -> &HashMap<ScriptBuf, SecretKey> {
        &self.secrets
    }

    /// Canonical UTXOs
    pub fn utxos(&self) -> impl Iterator<Item = (ScriptBuf, FullTxOut<ConfirmationBlockTime>)> {
        self.graph.graph().filter_chain_unspents(
            &self.chain,
            self.chain.tip().block_id(),
            CanonicalizationParams::default(),
            self.graph.index.outpoints().clone(),
        )
    }
}

/// Methods for syncing with `bdk_bitcoind_rpc`.
impl SpkTracker {
    pub fn tip(&self) -> CheckPoint {
        self.chain.tip()
    }

    pub fn expected_mempool_txs(&self) -> impl Iterator<Item = Arc<Transaction>> {
        self.graph
            .graph()
            .list_canonical_txs(&self.chain, self.chain.tip().block_id(), Default::default())
            .filter(|c_tx| c_tx.chain_position.is_unconfirmed())
            .map(|c_tx| c_tx.tx_node.tx)
    }

    pub fn consume_block_event(&mut self, event: BlockEvent<Block>) -> anyhow::Result<()> {
        let changeset = self
            .graph
            .apply_block_relevant(&event.block, event.block_height());
        self.stage.merge(changeset.into());
        let changeset = self.chain.apply_update(event.checkpoint)?;
        self.stage.merge(changeset.into());
        Ok(())
    }

    pub fn consume_mempool_event(&mut self, event: MempoolEvent) {
        let changeset = self.graph.batch_insert_relevant_unconfirmed(event.update);
        self.stage.merge(changeset.into());
        let changeset = self.graph.batch_insert_relevant_evicted_at(event.evicted);
        self.stage.merge(changeset.into());
    }
}

#[cfg(test)]
mod tests {}
