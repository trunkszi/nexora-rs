//! Public lifecycle evidence for cancelled application timers.
use std::{cell::Cell, rc::Rc, time::Duration};

use nexora::{ClientConfig, HttpClient, Proactor, Result};

#[test]
fn cancelled_timer_never_calls_expiry() -> Result<()> {
    let mut ring = Proactor::builder().build()?;
    let mut client = HttpClient::new(
        &mut ring,
        ClientConfig {
            dns_servers_csv: Some("127.0.0.1".into()),
            ..ClientConfig::default()
        },
    )?;
    let fired = Rc::new(Cell::new(false));
    let observed = Rc::clone(&fired);
    client.set_timer(&mut ring, Duration::from_secs(60), move |_, _| {
        observed.set(true)
    })?;
    ring.shutdown_with(&mut client)?;
    assert!(
        !fired.get(),
        "cancelled 60-second timer fired immediately during ring shutdown"
    );
    Ok(())
}
