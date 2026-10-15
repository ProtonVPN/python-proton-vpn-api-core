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
//! nftables kill switch for WireGuard-based connections.
//!
//! Two independent tables, each with three drop-by-default chains — `input`,
//! `output` and `forward` — so inbound, outbound and forwarded (e.g. from
//! VMs/containers) traffic is all blocked unless a rule allows it.
//!
//! # The kill switch: `inet proton_vpn_ks`
//!
//! [`FirewallKillSwitch::enable`] installs it, covering both address families.
//! Allowed traffic is:
//!
//! - loopback, in both directions
//! - established/related return traffic
//! - the WireGuard tunnel interface, and packets tagged with the fwmark
//! - LAN, link-local and multicast subnets
//! - NDP (IPv6 neighbor/router discovery) and DHCPv4, both as a client and as
//!   the server for NAT'd VMs/containers
//! - the VPN server IP during the connecting phase, when
//!   [`FirewallConfig::server_ip`] is set
//!
//! [`FirewallKillSwitch::disable`] removes the table entirely.
//!
//! # IPv6 leak protection: `ip6 proton_vpn_ks_ipv6`
//!
//! [`FirewallKillSwitch::enable_ipv6_leak_protection`] installs a second table
//! that blocks IPv6 while leaving IPv4 untouched. Its rules are a subset of the
//! kill switch's, restricted to IPv6, plus explicit DHCPv6.
//!
//! It is separate because the client asks for it when the kill switch is
//! *off* — the minimum protection you get without one — so it has to survive
//! [`FirewallKillSwitch::disable`]. IPv6 reaches the VPN inside the IPv4
//! tunnel, so tunneled IPv6 stays permitted.
//!
//! # Both tables
//!
//! Whatever is not accepted is rejected at the end of the output and forward
//! chains, so blocked traffic fails at once instead of hanging until a timeout:
//! TCP gets an RST, anything else an ICMP no-route. The input chain drops
//! silently, to avoid advertising the host to unsolicited inbound. The chains'
//! drop policies remain as the fail-closed backstop.
//!
//! Everything here requires `CAP_NET_ADMIN` (netlink/netfilter access),
//! including [`FirewallKillSwitch::list_installed_tables`], which only reads.
//!
//! # Ownership
//!
//! The tables are machine-wide, so the methods that change them take the
//! caller's uid: only the user who installed the kill switch, or root, may
//! change it while a table is in place. One owner covers both tables. See
//! [`ownership`] for the rule and why it is tied to the tables.
//!
//! [`FirewallKillSwitch::apply_rules`] is the exception: it is the boot
//! one-shot's rules-only path and never looks at or records an owner.
//!
//! # Known limitations
//!
//! - **LAN blocking not supported.** Local-network traffic is always allowed;
//!   there is no mode that also blocks the LAN yet.
//! - **Port forwarding not supported.** Inbound connections initiated from the
//!   VPN side (e.g. ProtonVPN NAT-PMP) are dropped for now; only return
//!   traffic for connections this host started is allowed in.

mod expr;
mod netlink;
pub mod ownership;
mod rules;
mod tables;

use super::config::FirewallConfig;
use super::error::{Error, Result};
use super::systemd;
use ownership::{State, StateStore};
use tables::Tables;

pub struct FirewallKillSwitch {
    tables: Box<dyn Tables>,
    boot_unit: Box<dyn systemd::BootUnit>,
    // The owner: any local user can reach the service, but only the one who
    // turned the kill switch on may turn it off.
    state: StateStore,
}

impl Default for FirewallKillSwitch {
    fn default() -> Self {
        Self {
            tables: Box::new(tables::NftTables),
            boot_unit: Box::new(systemd::SystemdBootUnit),
            state: StateStore::default(),
        }
    }
}

impl FirewallKillSwitch
{
    /// Substitute the netfilter, boot-persistence and state backends. Tests
    /// only; production goes through [`Default`].
    #[cfg(test)]
    fn with_backends(
        tables: Box<dyn Tables>,
        boot_unit: Box<dyn systemd::BootUnit>,
        state: StateStore,
    ) -> Self {
        Self {
            tables,
            boot_unit,
            state,
        }
    }

    /// Apply the kill switch rules, replacing any a previous call installed.
    ///
    /// Rules only, so it is safe for the boot one-shot, which runs before
    /// `dbus.service` exists. Ignores [`FirewallConfig::permanent`].
    ///
    /// Not owner-aware: it neither checks nor records an owner. At boot the
    /// owner recorded when permanent mode was turned on still applies.
    ///
    /// Idempotent: calling it twice leaves the same rule set in place.
    pub async fn apply_rules(&mut self, config: &FirewallConfig) -> Result<()> {
        self.tables.apply_kill_switch(config).await
    }

    /// Apply the rules on behalf of `caller`, recording them as its owner,
    /// without touching boot persistence.
    ///
    /// Fails with [`Error::NotOwner`], changing nothing, when another user
    /// owns the kill switch — see [`ownership`].
    ///
    /// Idempotent.
    pub async fn install(
        &mut self,
        caller: u32,
        config: &FirewallConfig,
    ) -> Result<()> {
        let previous = self.authorize(caller).await?;
        self.claim(caller)?;

        self.apply_rules(config)
            .await
            .inspect_err(|e| self.unclaim(previous.as_ref(), e))
    }

    /// [`install`](Self::install), then line up boot persistence with
    /// [`FirewallConfig::permanent`].
    ///
    /// Needs the system bus, so not usable at early boot — see
    /// [`Self::apply_rules`]. Rules go on first, so a failure never leaves the
    /// boot unit promising protection that was not applied.
    ///
    /// Idempotent.
    pub async fn enable(
        &mut self,
        caller: u32,
        config: &FirewallConfig,
    ) -> Result<()> {
        self.install(caller, config).await?;
        // A failure here keeps `caller` as the owner: the rules are up, and
        // they are its to remove.
        self.persist(config.permanent).await
    }

    /// Line up boot persistence with `permanent`.
    async fn persist(&self, permanent: bool) -> Result<()> {
        if permanent {
            self.boot_unit.enable().await
        } else {
            self.boot_unit.disable().await
        }
    }

    /// Remove the kill switch table on behalf of `caller`, leaving boot
    /// persistence alone.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    pub async fn uninstall(&mut self, caller: u32) -> Result<()> {
        self.authorize(caller).await?;
        self.remove_rules().await
    }

    /// Disable the kill switch on behalf of `caller`, removing the nftables
    /// table and turning boot persistence off.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    pub async fn disable(&mut self, caller: u32) -> Result<()> {
        // Before anything else, or a non-owner could switch off the owner's
        // boot unit.
        let state = self.authorize(caller).await?;
        let owner = state.map(|state| state.owner_uid);

        // Both run unconditionally: a boot unit that cannot be updated must
        // not leave the user stuck behind a firewall they asked to remove.
        let persisted = if ownership::may_change_boot_unit(caller, owner) {
            self.persist(false).await
        } else {
            log::warn!("Leaving the boot unit of uid {owner:?} to its owner");
            Ok(())
        };
        let removed = self.remove_rules().await;

        removed.and(persisted)
    }

    /// Remove the kill switch table, leaving boot persistence and the owner
    /// alone.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    async fn remove_rules(&mut self) -> Result<()> {
        self.tables.remove_kill_switch().await
    }

    /// Enable IPv6 leak protection on behalf of `caller`: block IPv6 that is
    /// not going through the tunnel, leaving IPv4 untouched.
    ///
    /// This lives in its own table because it has a lifetime independent of the
    /// full kill switch — the client asks for it precisely when the kill switch
    /// is *off*, so it has to survive [`disable`](Self::disable). It shares the
    /// kill switch's owner, though.
    ///
    /// Reads `tunnel_iface` and `fwmark` from `config`. The server IP does not
    /// apply: it admits the encrypted outer packets during connection setup, and
    /// those are IPv4.
    ///
    /// Idempotent: calling it twice leaves the same rule set in place.
    ///
    /// The two tables are meant to be mutually exclusive. These rules are a
    /// subset of the full kill switch's.
    pub async fn enable_ipv6_leak_protection(
        &mut self,
        caller: u32,
        config: &FirewallConfig,
    ) -> Result<()> {
        let previous = self.authorize(caller).await?;
        self.claim(caller)?;

        self.tables
            .apply_ipv6_leak_protection(config)
            .await
            .inspect_err(|e| self.unclaim(previous.as_ref(), e))
    }

    /// The kill switch tables currently installed, in a stable order, each as
    /// `"<family> <name>"` — the form `nft list table` expects.
    ///
    /// Presence only — the names are all a table dump gives us. Reading the
    /// rules back would mean parsing every expression out of netlink, and
    /// `nft list table` already does that far better.
    ///
    /// Takes `&self` rather than `&mut self` since it changes nothing, but it
    /// still requires `CAP_NET_ADMIN`: netfilter demands it even to read.
    pub async fn list_installed_tables(&self) -> Result<Vec<String>> {
        self.tables.installed().await
    }

    /// Disable IPv6 leak protection on behalf of `caller` by removing its
    /// nftables table.
    ///
    /// Idempotent: succeeds even when it was never enabled. Leaves the full kill
    /// switch table alone.
    pub async fn disable_ipv6_leak_protection(
        &mut self,
        caller: u32,
    ) -> Result<()> {
        self.authorize(caller).await?;
        self.tables.remove_ipv6_leak_protection().await
    }

    /// The recorded owner's uid, `None` when there is none or it cannot be
    /// read. Only meaningful while a table is installed — see [`ownership`].
    pub fn owner(&self) -> Option<u32> {
        self.state.owner()
    }

    /// Refuse `caller` unless [`ownership::authorize`] lets it through,
    /// returning the record it checked against.
    async fn authorize(&self, caller: u32) -> Result<Option<State>> {
        let installed = !self.list_installed_tables().await?.is_empty();
        let state = self.state.load();
        let owner = state.as_ref().map(|state| state.owner_uid);

        ownership::authorize(caller, owner, installed)
            .inspect_err(|e| log::warn!("Refusing uid {caller}: {e}"))?;

        Ok(state)
    }

    /// Record `caller` as the owner.
    ///
    /// Done *before* installing, so a crash in between leaves a table its
    /// owner can still remove. If the record cannot be written, nothing is
    /// installed: a table nobody but root could remove is worse than none.
    fn claim(&self, caller: u32) -> Result<()> {
        self.state.save(&State { owner_uid: caller })
    }

    /// Undo [`claim`](Self::claim) after the change it guarded failed.
    ///
    /// Not for [`Error::Persistence`]: the rules are up then, and they belong
    /// to the new owner.
    fn unclaim(&self, previous: Option<&State>, err: &Error) {
        if matches!(err, Error::Persistence(_)) {
            return;
        }

        // Logged rather than returned: the caller wants to know why the
        // change failed, not that tidying up after it did too.
        if let Err(e) = self.state.restore(previous) {
            log::error!("Could not restore the kill switch owner: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::super::error::{PersistenceError, RulesetError};
    use super::ownership::{NotOwner, TempDir, ROOT_UID};
    use super::*;

    const A: u32 = 1000;
    const B: u32 = 1001;

    const KS_TABLE: &str = "inet proton_vpn_ks";
    const IPV6_TABLE: &str = "ip6 proton_vpn_ks_ipv6";

    /// Records what `persist` asked for. Cloneable so the test keeps a handle
    /// after the kill switch takes ownership of one.
    #[derive(Clone, Default)]
    struct SpyBootUnit {
        enabled: Arc<AtomicUsize>,
        disabled: Arc<AtomicUsize>,
        /// Make `enable` fail, as when systemd cannot be reached.
        fail_enable: bool,
        /// Same, for `disable`.
        fail_disable: bool,
    }

    impl SpyBootUnit {
        fn calls(&self) -> usize {
            self.enabled.load(Ordering::SeqCst)
                + self.disabled.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl systemd::BootUnit for SpyBootUnit {
        async fn enable(&self) -> Result<()> {
            self.enabled.fetch_add(1, Ordering::SeqCst);
            if self.fail_enable {
                return Err(PersistenceError::NotApplied(
                    systemd::BOOT_UNIT,
                    "enabled",
                )
                .into());
            }
            Ok(())
        }
        async fn disable(&self) -> Result<()> {
            self.disabled.fetch_add(1, Ordering::SeqCst);
            if self.fail_disable {
                return Err(PersistenceError::NotApplied(
                    systemd::BOOT_UNIT,
                    "disabled",
                )
                .into());
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTablesState {
        installed: BTreeSet<&'static str>,
        /// Every call that would have changed a table.
        changes: Vec<&'static str>,
        fail_apply: bool,
        /// Removal reports an error, though the table is gone regardless.
        fail_remove: bool,
    }

    /// In-memory [`Tables`]. Cloneable for the same reason as
    /// [`SpyBootUnit`].
    #[derive(Clone, Default)]
    struct FakeTables(Arc<Mutex<FakeTablesState>>);

    impl FakeTables {
        fn state(&self) -> MutexGuard<'_, FakeTablesState> {
            self.0.lock().unwrap()
        }

        fn with_installed(tables: &[&'static str]) -> Self {
            let fake = Self::default();
            fake.state().installed.extend(tables);
            fake
        }

        fn installed_tables(&self) -> Vec<&'static str> {
            self.state().installed.iter().copied().collect()
        }

        fn changes(&self) -> Vec<&'static str> {
            self.state().changes.clone()
        }

        /// What a reboot does to non-permanent rules.
        fn reboot(&self) {
            self.state().installed.clear();
        }

        fn fail_apply(&self) {
            self.state().fail_apply = true;
        }

        fn fail_remove(&self) {
            self.state().fail_remove = true;
        }

        fn apply(&self, call: &'static str, table: &'static str) -> Result<()> {
            let mut state = self.state();
            state.changes.push(call);
            if state.fail_apply {
                return Err(netlink_error());
            }
            state.installed.insert(table);
            Ok(())
        }

        fn remove(
            &self,
            call: &'static str,
            table: &'static str,
        ) -> Result<()> {
            let mut state = self.state();
            state.changes.push(call);
            state.installed.remove(table);
            if state.fail_remove {
                return Err(netlink_error());
            }
            Ok(())
        }
    }

    fn netlink_error() -> Error {
        RulesetError::NetlinkRejected(std::io::Error::other("fake")).into()
    }

    #[async_trait::async_trait]
    impl Tables for FakeTables {
        async fn apply_kill_switch(&self, _: &FirewallConfig) -> Result<()> {
            self.apply("apply_kill_switch", KS_TABLE)
        }
        async fn remove_kill_switch(&self) -> Result<()> {
            self.remove("remove_kill_switch", KS_TABLE)
        }
        async fn apply_ipv6_leak_protection(
            &self,
            _: &FirewallConfig,
        ) -> Result<()> {
            self.apply("apply_ipv6_leak_protection", IPV6_TABLE)
        }
        async fn remove_ipv6_leak_protection(&self) -> Result<()> {
            self.remove("remove_ipv6_leak_protection", IPV6_TABLE)
        }
        async fn installed(&self) -> Result<Vec<String>> {
            Ok(self
                .installed_tables()
                .into_iter()
                .map(String::from)
                .collect())
        }
    }

    /// A kill switch over fakes, with handles to inspect them. The temp dir
    /// lives as long as the fixture.
    struct Fixture {
        ks: FirewallKillSwitch,
        tables: FakeTables,
        boot_unit: SpyBootUnit,
        dir: TempDir,
    }

    impl Fixture {
        fn new(test: &str) -> Self {
            Self::with(test, FakeTables::default(), SpyBootUnit::default())
        }

        fn with(
            test: &str,
            tables: FakeTables,
            boot_unit: SpyBootUnit,
        ) -> Self {
            let dir = TempDir::new(test);
            let ks = FirewallKillSwitch::with_backends(
                Box::new(tables.clone()),
                Box::new(boot_unit.clone()),
                StateStore::new(dir.path()),
            );

            Self {
                ks,
                tables,
                boot_unit,
                dir,
            }
        }

        fn store(&self) -> StateStore {
            StateStore::new(self.dir.path())
        }

        fn set_owner(&self, owner_uid: u32) {
            self.store().save(&State { owner_uid }).unwrap();
        }
    }

    fn config(permanent: bool) -> FirewallConfig {
        FirewallConfig {
            permanent,
            ..FirewallConfig::default()
        }
    }

    fn is_not_owner(result: Result<()>, owner: u32) -> bool {
        matches!(
            result,
            Err(Error::NotOwner(NotOwner::OwnedBy(o))) if o == owner
        )
    }

    /// (enable calls, disable calls) after one `persist`.
    async fn persist_calls(permanent: bool) -> (usize, usize) {
        let fixture = Fixture::new(&format!("persist_calls_{permanent}"));

        fixture.ks.persist(permanent).await.unwrap();

        (
            fixture.boot_unit.enabled.load(Ordering::SeqCst),
            fixture.boot_unit.disabled.load(Ordering::SeqCst),
        )
    }

    #[tokio::test]
    async fn permanent_mode_enables_the_boot_unit() {
        assert_eq!(persist_calls(true).await, (1, 0));
    }

    #[tokio::test]
    async fn non_permanent_mode_disables_the_boot_unit() {
        // Not a no-op: the user may be switching permanent off, and leaving
        // the unit enabled would resurrect the kill switch at the next boot.
        assert_eq!(persist_calls(false).await, (0, 1));
    }

    #[tokio::test]
    async fn enable_records_the_caller_as_owner() {
        let mut fixture = Fixture::new("enable_records_the_caller_as_owner");

        fixture.ks.enable(A, &config(false)).await.unwrap();

        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE]);
        assert_eq!(fixture.ks.owner(), Some(A));
    }

    #[tokio::test]
    async fn ipv6_leak_protection_alone_makes_the_caller_the_owner() {
        // One owner covers both tables: IPv6 leak protection on its own is
        // enough to lock other users out of the kill switch too.
        let mut fixture = Fixture::new("ipv6_leak_protection_alone");

        fixture
            .ks
            .enable_ipv6_leak_protection(A, &config(false))
            .await
            .unwrap();

        assert_eq!(fixture.tables.installed_tables(), [IPV6_TABLE]);
        assert_eq!(fixture.ks.owner(), Some(A));
        assert!(is_not_owner(fixture.ks.enable(B, &config(false)).await, A));
    }

    #[tokio::test]
    async fn a_non_owner_can_change_nothing() {
        // B must not be able to undo, or replace, the protection A turned on,
        // and refusing must not have touched the tables or the boot unit.
        let mut fixture = Fixture::new("a_non_owner_can_change_nothing");
        fixture.ks.enable(A, &config(true)).await.unwrap();
        fixture
            .ks
            .enable_ipv6_leak_protection(A, &config(false))
            .await
            .unwrap();
        let changes = fixture.tables.changes();
        let boot_unit_calls = fixture.boot_unit.calls();

        let ks = &mut fixture.ks;
        assert!(is_not_owner(ks.enable(B, &config(false)).await, A));
        assert!(is_not_owner(ks.install(B, &config(false)).await, A));
        assert!(is_not_owner(ks.disable(B).await, A));
        assert!(is_not_owner(ks.uninstall(B).await, A));
        assert!(is_not_owner(
            ks.enable_ipv6_leak_protection(B, &config(false)).await,
            A
        ));
        assert!(is_not_owner(ks.disable_ipv6_leak_protection(B).await, A));

        assert_eq!(fixture.tables.changes(), changes);
        assert_eq!(fixture.boot_unit.calls(), boot_unit_calls);
        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE, IPV6_TABLE]);
        assert_eq!(fixture.ks.owner(), Some(A));
    }

    #[tokio::test]
    async fn a_non_owner_disable_leaves_the_boot_unit_alone() {
        // Checked before persist(false), or B could stop the kill switch
        // coming back at the next boot.
        let mut fixture =
            Fixture::new("a_non_owner_disable_leaves_the_boot_unit_alone");
        fixture.ks.enable(A, &config(true)).await.unwrap();

        fixture.ks.disable(B).await.unwrap_err();

        assert_eq!(fixture.boot_unit.disabled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_owner_may_re_enable_and_disable() {
        let mut fixture = Fixture::new("the_owner_may_re_enable_and_disable");
        fixture.ks.enable(A, &config(false)).await.unwrap();

        fixture.ks.enable(A, &config(true)).await.unwrap();
        let disabled = fixture.boot_unit.disabled.load(Ordering::SeqCst);
        fixture.ks.disable(A).await.unwrap();

        assert!(fixture.tables.installed_tables().is_empty());
        assert_eq!(
            fixture.boot_unit.disabled.load(Ordering::SeqCst),
            disabled + 1
        );
    }

    #[tokio::test]
    async fn root_may_always_change_it() {
        let mut fixture = Fixture::new("root_may_always_change_it");
        fixture.ks.enable(A, &config(false)).await.unwrap();
        fixture
            .ks
            .enable_ipv6_leak_protection(A, &config(false))
            .await
            .unwrap();

        fixture.ks.disable(ROOT_UID).await.unwrap();
        fixture
            .ks
            .disable_ipv6_leak_protection(ROOT_UID)
            .await
            .unwrap();
        fixture.ks.enable(ROOT_UID, &config(false)).await.unwrap();

        assert_eq!(fixture.ks.owner(), Some(ROOT_UID));
    }

    #[tokio::test]
    async fn a_stale_owner_is_ignored_once_the_tables_are_gone() {
        // A non-permanent kill switch does not survive a reboot, but its
        // record does. It must not lock the next user out.
        let mut fixture =
            Fixture::new("a_stale_owner_is_ignored_once_the_tables_are_gone");
        fixture.ks.enable(A, &config(false)).await.unwrap();
        fixture.tables.reboot();

        fixture.ks.enable(B, &config(false)).await.unwrap();

        assert_eq!(fixture.ks.owner(), Some(B));
    }

    #[tokio::test]
    async fn a_table_with_no_owner_is_root_only() {
        // E.g. installed before ownership existed: fail closed.
        let mut fixture = Fixture::with(
            "a_table_with_no_owner_is_root_only",
            FakeTables::with_installed(&[KS_TABLE]),
            SpyBootUnit::default(),
        );

        let result = fixture.ks.disable(A).await;

        assert!(matches!(result, Err(Error::NotOwner(NotOwner::Unknown))));
        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE]);
        fixture.ks.disable(ROOT_UID).await.unwrap();
    }

    #[tokio::test]
    async fn a_table_with_a_corrupt_owner_is_root_only() {
        let mut fixture = Fixture::new("a_table_with_a_corrupt_owner");
        fixture.ks.enable(A, &config(false)).await.unwrap();
        std::fs::write(
            fixture.dir.path().join("firewall-kill-switch.json"),
            b"not json",
        )
        .unwrap();

        let result = fixture.ks.disable(A).await;

        assert!(matches!(result, Err(Error::NotOwner(NotOwner::Unknown))));
        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE]);
    }

    #[tokio::test]
    async fn a_failed_apply_restores_the_previous_owner() {
        let mut fixture =
            Fixture::new("a_failed_apply_restores_the_previous_owner");
        fixture.set_owner(A);
        fixture.tables.fail_apply();

        fixture.ks.enable(B, &config(false)).await.unwrap_err();
        assert_eq!(fixture.ks.owner(), Some(A));

        fixture
            .ks
            .enable_ipv6_leak_protection(B, &config(false))
            .await
            .unwrap_err();
        assert_eq!(fixture.ks.owner(), Some(A));
    }

    #[tokio::test]
    async fn a_failed_first_apply_leaves_no_owner() {
        let mut fixture = Fixture::new("a_failed_first_apply_leaves_no_owner");
        fixture.tables.fail_apply();

        fixture.ks.enable(A, &config(false)).await.unwrap_err();

        assert_eq!(fixture.store().load(), None);
    }

    #[tokio::test]
    async fn a_persistence_failure_keeps_the_new_owner() {
        // The rules are up, so they are the caller's to remove.
        let boot_unit = SpyBootUnit {
            fail_enable: true,
            ..SpyBootUnit::default()
        };
        let mut fixture = Fixture::with(
            "a_persistence_failure_keeps_the_new_owner",
            FakeTables::default(),
            boot_unit,
        );

        let result = fixture.ks.enable(A, &config(true)).await;

        assert!(matches!(result, Err(Error::Persistence(_))));
        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE]);
        assert_eq!(fixture.ks.owner(), Some(A));
    }

    #[tokio::test]
    async fn nothing_is_applied_when_the_owner_cannot_be_recorded() {
        // A table nobody but root could remove is worse than none.
        let dir = TempDir::new("nothing_is_applied_when_the_owner_cannot");
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let tables = FakeTables::default();
        let mut ks = FirewallKillSwitch::with_backends(
            Box::new(tables.clone()),
            Box::new(SpyBootUnit::default()),
            StateStore::new(not_a_dir.join("state")),
        );

        let result = ks.enable(A, &config(false)).await;
        assert!(matches!(result, Err(Error::State(_))));

        let result = ks.enable_ipv6_leak_protection(A, &config(false)).await;
        assert!(matches!(result, Err(Error::State(_))));

        assert!(tables.changes().is_empty());
    }

    #[tokio::test]
    async fn the_owner_record_outlives_the_tables() {
        // Ignored once both tables are gone, but kept for the boot unit.
        let mut fixture = Fixture::new("the_owner_record_outlives_the_tables");
        fixture.ks.enable(A, &config(false)).await.unwrap();
        fixture
            .ks
            .enable_ipv6_leak_protection(A, &config(false))
            .await
            .unwrap();

        fixture.ks.disable(A).await.unwrap();
        fixture.ks.disable_ipv6_leak_protection(A).await.unwrap();
        assert_eq!(fixture.ks.owner(), Some(A));

        fixture.ks.enable(B, &config(false)).await.unwrap();
        assert_eq!(fixture.ks.owner(), Some(B));
    }

    #[tokio::test]
    async fn uninstall_leaves_the_boot_unit_and_the_owner() {
        let mut fixture =
            Fixture::new("uninstall_leaves_the_boot_unit_and_the_owner");
        fixture.ks.install(A, &config(false)).await.unwrap();

        fixture.ks.uninstall(A).await.unwrap();

        assert!(fixture.tables.installed_tables().is_empty());
        assert_eq!(fixture.ks.owner(), Some(A));
        assert_eq!(fixture.boot_unit.calls(), 0);
    }

    #[tokio::test]
    async fn rules_the_boot_unit_brings_back_keep_their_owner() {
        // Turning permanent mode off failed, so the boot unit re-applies the
        // rules at the next boot: they must still be A's, or only root could
        // remove them.
        let boot_unit = SpyBootUnit {
            fail_disable: true,
            ..SpyBootUnit::default()
        };
        let mut fixture = Fixture::with(
            "rules_the_boot_unit_brings_back_keep_their_owner",
            FakeTables::default(),
            boot_unit,
        );
        fixture.ks.enable(A, &config(true)).await.unwrap();

        let result = fixture.ks.disable(A).await;
        assert!(matches!(result, Err(Error::Persistence(_))));
        fixture.tables.reboot();
        fixture.ks.apply_rules(&config(false)).await.unwrap();

        assert_eq!(fixture.ks.owner(), Some(A));
        fixture.ks.uninstall(A).await.unwrap();
    }

    #[tokio::test]
    async fn rules_brought_back_after_fwks_down_keep_their_owner() {
        // `fwks down` removes the tables but not the boot unit.
        let mut fixture =
            Fixture::new("rules_brought_back_after_fwks_down_keep_their_owner");
        fixture.ks.enable(A, &config(true)).await.unwrap();

        fixture.ks.uninstall(ROOT_UID).await.unwrap();
        fixture.ks.apply_rules(&config(false)).await.unwrap();

        assert_eq!(fixture.ks.owner(), Some(A));
        fixture.ks.disable(A).await.unwrap();
    }

    #[tokio::test]
    async fn a_non_owner_cannot_turn_off_a_boot_unit_with_no_table() {
        // The boot unit failed to bring A's rules back this boot. B may act,
        // since nothing is installed, but must not stop them coming back at
        // the next one.
        let mut fixture = Fixture::new("a_non_owner_cannot_turn_off_a_boot_unit");
        fixture.ks.enable(A, &config(true)).await.unwrap();
        fixture.tables.reboot();

        fixture.ks.disable(B).await.unwrap();
        assert_eq!(fixture.boot_unit.disabled.load(Ordering::SeqCst), 0);

        fixture.ks.disable(A).await.unwrap();
        assert_eq!(fixture.boot_unit.disabled.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn anyone_may_turn_off_the_boot_unit_with_no_record() {
        // A machine where the kill switch was never used.
        let mut fixture =
            Fixture::new("anyone_may_turn_off_the_boot_unit_with_no_record");

        fixture.ks.disable(B).await.unwrap();

        assert_eq!(fixture.boot_unit.disabled.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_removal_error_is_reported() {
        let mut fixture = Fixture::new("a_removal_error_is_reported");
        fixture.ks.enable(A, &config(false)).await.unwrap();
        fixture.tables.fail_remove();

        let result = fixture.ks.disable(A).await;

        assert!(matches!(result, Err(Error::Ruleset(_))));
    }

    #[tokio::test]
    async fn apply_rules_leaves_the_owner_alone() {
        // The boot one-shot's path: rules only.
        let mut fixture = Fixture::new("apply_rules_leaves_the_owner_alone");
        fixture.set_owner(A);

        fixture.ks.apply_rules(&config(false)).await.unwrap();

        assert_eq!(fixture.tables.installed_tables(), [KS_TABLE]);
        assert_eq!(fixture.ks.owner(), Some(A));
        assert_eq!(fixture.boot_unit.calls(), 0);
    }
}
