use crate::models::SecurityEvent;

pub trait KernelMonitor {
    fn attach(&mut self) -> anyhow::Result<()>;
    fn detach(&mut self) -> anyhow::Result<()>;
    fn on_event(&mut self, event: &SecurityEvent) -> anyhow::Result<()>;
}

#[derive(Default)]
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::{EbpfMonitor, KernelMonitor};
    use crate::models::{EventType, SecurityEvent, ThreatLevel};

    #[test]
    fn attach_returns_expected_error() {
        let mut monitor = EbpfMonitor;
        let err = monitor.attach().expect_err("attach should fail in v0.1");
        assert!(
            err.to_string().contains("eBPF support coming in v0.2"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn detach_returns_expected_error() {
        let mut monitor = EbpfMonitor;
        let err = monitor.detach().expect_err("detach should fail in v0.1");
        assert!(
            err.to_string().contains("eBPF support coming in v0.2"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn on_event_returns_expected_error() {
        let mut monitor = EbpfMonitor;
        let event = SecurityEvent::new(
            EventType::ProcessNew,
            ThreatLevel::Green,
            "test event".to_string(),
        );
        let err = monitor
            .on_event(&event)
            .expect_err("on_event should fail in v0.1");
        assert!(
            err.to_string().contains("eBPF support coming in v0.2"),
            "unexpected error: {err}"
        );
    }
}
