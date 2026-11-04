//! Rules explicitly authorized during a per-user installation. The exact exe
//! path owns two allow rules; updates at that path keep the same identities.
use super::{Action, Direction, StoredRule, normalize_program_path};
use std::path::Path;

struct Rule {
    name: String,
    program: String,
    protocol: u32,
}

fn rules(exe: &Path) -> [Rule; 2] {
    let program = normalize_program_path(&exe.to_string_lossy());
    [17, 6].map(|protocol| Rule {
        name: format!(
            "MeshHarbor Install {}-In ({program})",
            if protocol == 17 { "UDP" } else { "TCP" }
        ),
        program: program.clone(),
        protocol,
    })
}

impl Rule {
    fn owns(&self, rule: &StoredRule) -> bool {
        rule.display_name.as_deref() == Some(self.name.as_str())
            && rule.action == Some(Action::Allow)
            && rule.direction == Some(Direction::In)
            && rule.protocol == Some(self.protocol)
            && rule
                .program
                .as_deref()
                .is_some_and(|program| normalize_program_path(program) == self.program)
    }

    fn current(&self, store: &[StoredRule], public: bool) -> bool {
        let owned: Vec<_> = store.iter().filter(|r| self.owns(r)).collect();
        let [rule] = owned.as_slice() else {
            return false;
        };
        let mut profiles: Vec<_> = rule
            .profiles
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect();
        profiles.sort();
        profiles.dedup();
        let expected = if public {
            vec!["domain", "private", "public"]
        } else {
            vec!["domain", "private"]
        };
        rule.active == Some(true)
            && (profiles == expected || (public && profiles.is_empty()))
            && rule.keys.iter().all(|key| {
                [
                    "action",
                    "active",
                    "dir",
                    "protocol",
                    "app",
                    "name",
                    "desc",
                    "embedctxt",
                    "profile",
                ]
                .contains(&key.to_ascii_lowercase().as_str())
            })
    }

    fn add_args(&self, public: bool) -> Vec<String> {
        vec![
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={}", self.name),
            "dir=in".into(),
            "action=allow".into(),
            format!("protocol={}", self.protocol),
            format!("program={}", self.program),
            format!(
                "profile=domain,private{}",
                if public { ",public" } else { "" }
            ),
        ]
    }
}

#[cfg(windows)]
mod effects {
    use super::*;
    use crate::winfw::{powershell_remove_args, read_local_store, run_bounded};
    use anyhow::{Context, Result, bail};
    use std::time::Duration;

    fn remove_ids(ids: &[&str]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let output = run_bounded(
            "powershell.exe",
            &powershell_remove_args(ids),
            Duration::from_secs(30),
        )
        .map_err(|error| anyhow::anyhow!("firewall removal did not finish: {error:?}"))?;
        if !output.status.success() {
            bail!("firewall removal failed; administrator approval is required")
        }
        Ok(())
    }

    pub fn has_rules(exe: &Path) -> Result<bool> {
        let store = read_local_store().context("read the local firewall store")?;
        Ok(rules(exe)
            .iter()
            .any(|rule| store.iter().any(|entry| rule.owns(entry))))
    }

    pub fn prepare(exe: &Path, public: bool) -> Result<()> {
        if crate::winfw::hygiene_disabled(crate::env::node_env("TUN_HYGIENE").as_deref()) {
            bail!("firewall preparation is disabled by TUN_HYGIENE")
        }
        let store = read_local_store().context("read the local firewall store")?;
        for rule in rules(exe) {
            if rule.current(&store, public) {
                continue;
            }
            let ids: Vec<_> = store
                .iter()
                .filter(|r| rule.owns(r))
                .map(|r| r.id.as_str())
                .collect();
            remove_ids(&ids)?;
            let output = run_bounded("netsh", &rule.add_args(public), Duration::from_secs(10))
                .map_err(|error| anyhow::anyhow!("firewall rule add did not finish: {error:?}"))?;
            if !output.status.success() {
                bail!(
                    "could not add the MeshHarbor firewall rule; administrator approval is required"
                )
            }
        }
        // Only Windows' prompt-written blocks for this exact path; deliberate
        // administrator blocks remain the owner's policy floor.
        let _ = crate::winfw::remove_prompt_block_rules_for(exe, Duration::from_secs(30));
        let store = read_local_store().context("verify the local firewall store")?;
        if !rules(exe).iter().all(|r| r.current(&store, public))
            || !crate::winfw::prompt_block_rules_for_program(&store, &exe.to_string_lossy())
                .is_empty()
        {
            bail!("firewall preparation is incomplete; the expected rules were not verified")
        }
        Ok(())
    }

    pub fn remove(exe: &Path) -> Result<()> {
        let store = read_local_store().context("read the local firewall store")?;
        let specs = rules(exe);
        let ids: Vec<_> = store
            .iter()
            .filter(|r| specs.iter().any(|s| s.owns(r)))
            .map(|r| r.id.as_str())
            .collect();
        remove_ids(&ids)?;
        if has_rules(exe)? {
            bail!("MeshHarbor installer firewall rules remain after removal")
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use effects::{has_rules, prepare, remove};

#[cfg(test)]
mod tests {
    use super::*;
    fn stored(rule: &Rule, profiles: &str) -> StoredRule {
        super::super::parse_stored_rule(
            "{owned}",
            &format!(
                "v2.30|Name={}|Action=Allow|Active=TRUE|Dir=In|Protocol={}|App={}|{}",
                rule.name, rule.protocol, rule.program, profiles
            ),
        )
        .unwrap()
    }

    #[test]
    fn installer_rules_default_to_private_domain_for_both_protocols() {
        let specs = rules(Path::new(r"C:\Users\user\Programs\meshharbord.exe"));
        assert_eq!([specs[0].protocol, specs[1].protocol], [17, 6]);
        for rule in specs {
            assert!(
                rule.add_args(false)
                    .contains(&"profile=domain,private".into())
            );
            assert!(!rule.add_args(false).iter().any(|s| s.contains("public")));
            assert!(
                rule.add_args(true)
                    .contains(&"profile=domain,private,public".into())
            );
            assert!(rule.current(&[stored(&rule, "Profile=Domain|Profile=Private|")], false));
            assert!(
                !rule.current(&[stored(&rule, "")], false),
                "an all-profile rule is too broad"
            );
            assert!(!rule.current(
                &[stored(
                    &rule,
                    "Profile=Domain|Profile=Private|Profile=Public|"
                )],
                false
            ));
        }
    }

    #[test]
    fn installer_ownership_is_exact_and_stable_across_updates() {
        let first = rules(Path::new(r"C:\Users\user\Programs\meshharbord.exe"));
        let updated = rules(Path::new(r"c:/users/user/programs/meshharbord.exe"));
        assert_eq!(first[0].name, updated[0].name);
        let rule = &first[0];
        let mut record = stored(rule, "Profile=Domain|Profile=Private|");
        assert!(rule.owns(&record));
        record.program = Some(r"C:\other\meshharbord.exe".into());
        assert!(!rule.owns(&record));
        record.program = Some(rule.program.clone());
        record.action = Some(Action::Block);
        assert!(
            !rule.owns(&record),
            "never delete an administrator's block rule"
        );
        record.action = Some(Action::Allow);
        record.display_name = Some("Other application".into());
        assert!(!rule.owns(&record));
    }
}
