// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------
//! Handing a finalized batch of nftables changes to the kernel.

use nftnl::FinalizedBatch;

use super::super::error::{Error, Result};

/// Send a batch to netfilter and wait for the kernel to acknowledge it.
///
/// The whole batch is applied as a single transaction: either every rule in it
/// lands or none do, so the host is never left half-protected. Requires
/// `CAP_NET_ADMIN`.
fn sync_send_and_process(batch: FinalizedBatch) -> Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(Error::NetlinkOpen)?;
    let portid = socket.portid();

    socket.send_all(&batch).map_err(Error::NetlinkSend)?;

    let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();

    while !expected_seqs.is_empty() {
        let messages =
            socket.recv(&mut buffer[..]).map_err(Error::NetlinkReceive)?;

        for message in messages {
            let message = message.map_err(Error::NetlinkReceive)?;
            let Some(expected_seq) = expected_seqs.next() else {
                // More ACKs than requests: the kernel is talking about
                // something we did not send, so stop rather than mismatch
                // responses against the wrong messages.
                break;
            };
            mnl::cb_run(message, expected_seq, portid)
                .map_err(Error::NetlinkRejected)?;
        }
    }

    Ok(())
}

/// Send a batch without blocking the async executor.
pub(super) async fn send_and_process(batch: FinalizedBatch) -> Result<()> {
    tokio::task::spawn_blocking(move || sync_send_and_process(batch))
        .await
        .map_err(Error::Runtime)?
}
