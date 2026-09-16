// Docker compute backend. Shells out to the `docker` CLI.
//
// No state is persisted here: the container's existence on the host IS the
// state, and `find_available_id` scans for `toon-<n>`. The lease that pays for
// it is bookkeeping the provider keeps separately (`provider::persistence`).
//
// CAPABILITIES (spec §4.4). This backend grants none, and `run_args` is the
// whole reason: a workload gets a name, CPU and memory limits, its port
// forwards, its environment and a NAMED VOLUME — never `--privileged`, never a
// `--device`, and never a host path. In particular the daemon socket this
// backend itself drives is on the provider's side of the workload boundary and
// is never mounted into a workload; a provider that did mount it would be
// handing one tenant every other tenant's containers.
//
// So `docker` is not deliverable here yet: it obliges the provider to run a
// daemon of the LEASE'S OWN at /var/run/docker.sock — the reference shape is a
// per-lease `dind` sidecar sharing a private network with the workload —
// accounted, with everything it runs, against the listing's `resources`.
// `capabilities::grant_refusal` refuses the grant at config load until that
// exists, so no listing published from this backend carries a `t` tag it
// cannot honour. `nesting` is refused for the same reason: it would mean
// tenant code holding kernel privileges this backend never hands out.

use std::process::Stdio;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::process::Command;

use crate::compute::{
    container_name, id_from_container_name, ComputeBackend, ContainerConfig, ContainerStatus,
    NodeStatus, SSH_CONTAINER_PORT, SSH_PUBLIC_KEY_ENV, WORKLOAD_NAME_PREFIX,
};

pub struct DockerBackend {
    /// `None` = the host's default `bridge`.
    network: Option<String>,
}

impl DockerBackend {
    pub fn new() -> Self {
        Self { network: None }
    }

    pub fn with_network(network: impl Into<String>) -> Self {
        Self {
            network: Some(network.into()),
        }
    }

    /// The full `docker` argv for a workload. Separate from `create_container`
    /// so a unit test can assert on the real argv without a daemon.
    fn run_args(&self, config: &ContainerConfig) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            container_name(config.id),
            "--restart".into(),
            "unless-stopped".into(),
            "--cpus".into(),
            format!("{:.3}", f64::from(config.cpu_millicores) / 1000.0),
            "--memory".into(),
            format!("{}m", config.memory_mb),
        ];

        if let Some(net) = &self.network {
            args.push("--network".into());
            args.push(net.clone());
        }

        // The SSH forward first, then the tenant's ports. The key rides in
        // as an environment variable: `docker run` cannot write a file into
        // an image before it starts, and every sshd image reads its keys
        // from somewhere different, so the image (or the spawn's
        // entrypoint) is what installs it.
        if let Some(host_port) = config.host_port {
            args.push("-p".into());
            args.push(format!("{}:{}/tcp", host_port, SSH_CONTAINER_PORT));
        }
        if let Some(key) = &config.ssh_key {
            args.push("-e".into());
            args.push(format!("{}={}", SSH_PUBLIC_KEY_ENV, key));
        }

        for port in &config.ports {
            args.push("-p".into());
            args.push(format!(
                "{}:{}/{}",
                port.host_port, port.container_port, port.protocol
            ));
        }

        for (k, v) in &config.env {
            args.push("-e".into());
            args.push(format!("{}={}", k, v));
        }

        // Named per workload id, so two leases never share state and a
        // re-spawn at the same id cannot inherit the last tenant's volume
        // (`delete_container` removes it).
        if let Some(path) = &config.data_path {
            args.push("-v".into());
            args.push(format!("{}-data:{}", container_name(config.id), path));
        }

        if let Some(entrypoint) = &config.entrypoint {
            args.push("--entrypoint".into());
            args.push(entrypoint.clone());
        }

        // The image separates the flags from the command: docker treats
        // everything after it as the workload's argv.
        args.push(config.image.clone());
        args.extend(config.args.iter().cloned());

        args
    }

    async fn docker(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new("docker")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("invoke docker CLI")
    }
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ComputeBackend for DockerBackend {
    async fn find_available_id(&self, range_start: u32, range_end: u32) -> Result<u32> {
        let name_filter = format!("name={}", WORKLOAD_NAME_PREFIX);
        let output = self
            .docker(&[
                "ps",
                "-a",
                "--format",
                "{{.Names}}",
                "--filter",
                &name_filter,
            ])
            .await?;
        let names = String::from_utf8_lossy(&output.stdout);
        let used: std::collections::HashSet<u32> =
            names.lines().filter_map(id_from_container_name).collect();
        for id in range_start..=range_end {
            if !used.contains(&id) {
                return Ok(id);
            }
        }
        anyhow::bail!(
            "no available container id in range {}..={}",
            range_start,
            range_end
        );
    }

    async fn create_container(&self, config: &ContainerConfig) -> Result<String> {
        let args = self.run_args(config);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self.docker(&arg_refs).await?;
        if !output.status.success() {
            anyhow::bail!(
                "docker run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    async fn start_container(&self, id: u32) -> Result<()> {
        let name = container_name(id);
        let output = self.docker(&["start", &name]).await?;
        if !output.status.success() {
            anyhow::bail!(
                "docker start {} failed: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    async fn stop_container(&self, id: u32) -> Result<()> {
        // Best-effort: an already-gone container must not fail the cleanup loop.
        let _ = self.docker(&["stop", &container_name(id)]).await;
        Ok(())
    }

    async fn delete_container(&self, id: u32) -> Result<()> {
        let name = container_name(id);
        let _ = self.docker(&["rm", "-f", &name]).await;
        // Remove the volume too, so a re-spawn at the same id cannot inherit
        // the last tenant's state.
        let volume = format!("{}-data", name);
        let _ = self.docker(&["volume", "rm", "-f", &volume]).await;
        Ok(())
    }

    async fn get_node_status(&self) -> Result<NodeStatus> {
        Ok(NodeStatus {
            cpu_usage: 0.0,
            memory_used: 0,
            memory_total: 0,
            disk_used: 0,
            disk_total: 0,
        })
    }

    async fn get_container_status(&self, id: u32) -> Result<ContainerStatus> {
        let name = container_name(id);
        let output = self
            .docker(&["inspect", "-f", "{{.State.Running}}", &name])
            .await?;
        if !output.status.success() {
            // `inspect` fails only when there is no such container.
            return Ok(ContainerStatus::Absent);
        }
        Ok(match String::from_utf8_lossy(&output.stdout).trim() {
            "true" => ContainerStatus::Running,
            _ => ContainerStatus::Stopped,
        })
    }

    async fn get_container_ip(&self, id: u32) -> Result<Option<String>> {
        let name = container_name(id);
        let output = self
            .docker(&["inspect", "-f", "{{.NetworkSettings.IPAddress}}", &name])
            .await?;
        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_for_is_deterministic() {
        assert_eq!(container_name(1234), "toon-1234");
    }

    #[test]
    fn run_args_carry_every_piece_of_the_config() {
        // Asserts on the real argv builder, so a change to `create_container`
        // cannot silently pass. Shelling out to docker is `tests/docker_backend`.
        let cfg = ContainerConfig {
            id: 42,
            name: "toon-42".to_string(),
            image: "alpine:latest".to_string(),
            cpu_millicores: 1500,
            memory_mb: 256,
            storage_gb: 1,
            ssh_key: Some("ssh-ed25519 AAAA tenant".to_string()),
            host_port: Some(30042),
            ports: vec![crate::compute::PortMapping {
                host_port: 17777,
                container_port: 7777,
                protocol: "tcp".to_string(),
            }],
            env: std::collections::HashMap::from([("FOO".to_string(), "bar".to_string())]),
            entrypoint: Some("/bin/sh".to_string()),
            args: vec!["sleep".to_string(), "300".to_string()],
            data_path: Some("/var/data".to_string()),
        };

        let args = DockerBackend::new().run_args(&cfg);

        assert!(args.contains(&"toon-42".to_string()));
        assert!(
            args.contains(&"1.500".to_string()),
            "millicores become a fractional --cpus"
        );
        assert!(
            args.contains(&"30042:22/tcp".to_string()),
            "the SSH forward"
        );
        assert!(args.contains(&"SSH_PUBLIC_KEY=ssh-ed25519 AAAA tenant".to_string()));
        assert!(args.contains(&"17777:7777/tcp".to_string()));
        assert!(args.contains(&"FOO=bar".to_string()));
        assert!(args.contains(&"toon-42-data:/var/data".to_string()));
        assert!(args.contains(&"256m".to_string()));

        // Everything after the image is the workload's argv, so every flag —
        // --entrypoint included — has to come before it.
        let image_at = args.iter().position(|a| a == "alpine:latest").unwrap();
        assert_eq!(
            &args[image_at + 1..],
            &["sleep".to_string(), "300".to_string()]
        );
        assert!(args[..image_at].contains(&"--entrypoint".to_string()));
    }

    #[test]
    fn the_workload_argv_never_exposes_the_host_daemon_or_any_privilege() {
        // Spec §4.4: the provider MUST NOT expose the daemon it runs its own
        // workloads with — not by bind-mounting its socket, not through a
        // device, not over TCP. Asserted on the argv rather than by reading
        // the code, because this is the line a future capability ticket is
        // most likely to cross by accident.
        let cfg = ContainerConfig {
            id: 42,
            name: "toon-42".to_string(),
            image: "alpine:latest".to_string(),
            cpu_millicores: 1500,
            memory_mb: 256,
            storage_gb: 1,
            ssh_key: Some("ssh-ed25519 AAAA tenant".to_string()),
            host_port: Some(30042),
            ports: vec![],
            env: std::collections::HashMap::from([("FOO".to_string(), "bar".to_string())]),
            entrypoint: None,
            args: vec![],
            data_path: Some("/data".to_string()),
        };

        let args = DockerBackend::with_network("toon-net").run_args(&cfg);

        for arg in &args {
            assert!(
                !arg.contains("docker.sock"),
                "the host daemon's socket is never a workload's: {}",
                arg
            );
            assert!(
                !arg.contains("/var/run"),
                "nothing of the host's runtime dir reaches a workload: {}",
                arg
            );
            assert!(
                !arg.starts_with("DOCKER_HOST="),
                "no workload is pointed at a daemon it was not given: {}",
                arg
            );
        }
        for flag in [
            "--privileged",
            "--device",
            "--cap-add",
            "--pid",
            "--userns",
            "--security-opt",
        ] {
            assert!(
                !args.iter().any(|a| a == flag),
                "{} is a privilege no listing on this backend grants",
                flag
            );
        }
        // The only mount is the lease's own named volume, never a host path.
        let mounts: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && args[i - 1] == "-v")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(mounts, vec![&"toon-42-data:/data".to_string()]);
        assert!(!mounts.iter().any(|m| m.starts_with('/')));
    }

    #[test]
    fn a_stateless_workload_gets_no_volume() {
        let cfg = ContainerConfig {
            id: 7,
            name: "toon-7".to_string(),
            image: "alpine:latest".to_string(),
            cpu_millicores: 1000,
            memory_mb: 64,
            storage_gb: 1,
            ssh_key: None,
            host_port: None,
            ports: vec![],
            env: std::collections::HashMap::new(),
            entrypoint: None,
            args: vec![],
            data_path: None,
        };
        let args = DockerBackend::new().run_args(&cfg);
        assert!(!args.contains(&"-v".to_string()));
        assert!(
            !args.contains(&"-p".to_string()),
            "no SSH forward without a key or port"
        );
        assert!(!args.iter().any(|a| a.starts_with("SSH_PUBLIC_KEY=")));
    }
}
