use log::debug;
use std::fs;
use std::path::Path;
use std::result::Result::Ok;

use crate::helpers::{
    CheckGroup, CheckGroupResult, CheckResult,
    CheckResultValue::{Errored, Failed, Passed},
    cpu,
    host_executor::HostNamespaceExecutor,
};
use crate::helpers::{CheckGroupCategory, kernel};
use futures::{FutureExt, future::join_all};

use async_trait::async_trait;

const GROUP_IDENTIFIER: &str = "kvm";
const NAME: &str = "KVM checks";

pub struct KvmChecks {
    host_executor: HostNamespaceExecutor,
}

impl KvmChecks {
    pub fn new(host_executor: HostNamespaceExecutor) -> Self {
        KvmChecks { host_executor }
    }

    async fn check_dev_kvm(&self) -> CheckResult {
        let name = String::from("/dev/kvm check");

        match self
            .host_executor
            .spawn_in_host_ns(async {
                if Path::new("/dev/kvm").exists() {
                    return true;
                }
                return false;
            })
            .await
        {
            Ok(true) => CheckResult::new(&name, Passed),
            Ok(false) => CheckResult::new(
                &name,
                Failed("/dev/kvm doesn't exist on the host".to_string()),
            ),
            Err(e) => {
                debug!("Error: {}", e);
                CheckResult::new(&name, Errored(e.to_string()))
            }
        }
    }

    #[allow(unused_mut)]
    async fn has_modules(&self) -> CheckResult {
        let name = String::from("Host contains the required modules for running edera on KVM");
        // On arm, this vector won't need to be mutable, but on x86 we will
        // need to push the kvm module names to it
        let mut required_modules: Vec<String> = vec!["vhost_vsock".to_string()];

        #[cfg(target_arch = "x86_64")]
        {
            // get the cpu vendor because based on who it is we will be checking for a different
            // kvm module
            let cpuinfo_res = match self
                .host_executor
                .spawn_in_host_ns(async { fs::read_to_string("/proc/cpuinfo") })
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    return CheckResult::new(&name, Errored(e.to_string()));
                }
            };

            // We need to match twice so we clarify whether the error was a JoinError
            // or an error from fs::read_to_string
            let cpuinfo = match cpuinfo_res {
                Ok(info) => info,
                Err(e) => {
                    return CheckResult::new(&name, Errored(e.to_string()));
                }
            };

            let cpu_vendor = cpu::extract_cpu_vendor(&cpuinfo);

            match cpu_vendor.as_str() {
                "GenuineIntel" => {
                    required_modules.push("kvm_intel".to_string());
                }
                "AuthenticAMD" => {
                    required_modules.push("kvm_amd".to_string());
                }
                _ => {
                    return CheckResult::new(
                        &name,
                        Errored(format!("Unknown CPU vendor: {cpu_vendor}")),
                    );
                }
            }
        }

        kernel::check_modules(name, &self.host_executor, &required_modules).await
    }

    pub async fn run_all(&self) -> CheckGroupResult {
        let results = join_all([self.has_modules().boxed(), self.check_dev_kvm().boxed()]).await;
        CheckGroupResult {
            name: NAME.to_string(),
            result: Passed,
            results,
        }
    }
}

#[async_trait]
impl CheckGroup for KvmChecks {
    fn id(&self) -> &str {
        GROUP_IDENTIFIER
    }

    fn name(&self) -> &str {
        NAME
    }

    fn description(&self) -> &str {
        "Running edera in a KVM environment checks"
    }

    async fn run(&self) -> CheckGroupResult {
        self.run_all().await
    }

    fn category(&self) -> CheckGroupCategory {
        CheckGroupCategory::Optional("".to_string())
    }
}
