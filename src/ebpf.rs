use crate::models::SecurityEvent;

pub trait KernelMonitor {
    fn attach(&mut self) -> anyhow::Result<()>;
    fn detach(&mut self) -> anyhow::Result<()>;
    fn on_event(&mut self, event: &SecurityEvent) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct EbpfMonitor;

impl KernelMonitor for EbpfMonitor {
    fn attach(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("eBPF support coming in v0.2");
    }

    fn detach(&mut self) -> anyhow::Result<()> {
        anyhow::bail!("eBPF support coming in v0.2");
    }

    fn on_event(&mut self, _event: &SecurityEvent) -> anyhow::Result<()> {
        anyhow::bail!("eBPF support coming in v0.2");
    }
}
