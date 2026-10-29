//! In-process event bus with a replay buffer, served as Server-Sent Events.

use eld_api::{time, Caller, Event, Object};
use std::collections::VecDeque;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

/// Events kept for replay (`?since=<id>`).
const BACKLOG: usize = 1000;

struct Inner {
    next: u64,
    backlog: VecDeque<Event>,
    subs: Vec<Sender<Event>>,
}

/// The bus.
pub struct Bus {
    inner: Mutex<Inner>,
}

impl Default for Bus {
    fn default() -> Self {
        Bus { inner: Mutex::new(Inner { next: 1, backlog: VecDeque::new(), subs: vec![] }) }
    }
}

impl Bus {
    /// Publishes an event and returns it.
    pub fn publish(&self, kind: &str, severity: &str, actor: Option<&Caller>, data: Object) -> Event {
        let mut i = self.inner.lock().unwrap();
        let ev = Event {
            id: i.next,
            time: time::now_rfc3339(),
            kind: kind.into(),
            severity: severity.into(),
            actor: actor.cloned(),
            data,
        };
        i.next += 1;
        if i.backlog.len() == BACKLOG {
            i.backlog.pop_front();
        }
        i.backlog.push_back(ev.clone());
        // Drop subscribers whose receiver is gone.
        i.subs.retain(|s| s.send(ev.clone()).is_ok());
        ev
    }

    /// Subscribes; returns buffered events with id > `since` and a receiver
    /// for new ones.
    pub fn subscribe(&self, since: u64) -> (Vec<Event>, Receiver<Event>) {
        let mut i = self.inner.lock().unwrap();
        let backlog = i.backlog.iter().filter(|e| e.id > since).cloned().collect();
        let (tx, rx) = channel();
        i.subs.push(tx);
        (backlog, rx)
    }

    /// Buffered events with id > `since`.
    pub fn since(&self, since: u64) -> Vec<Event> {
        self.inner.lock().unwrap().backlog.iter().filter(|e| e.id > since).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_and_live() {
        let b = Bus::default();
        b.publish("a", "info", None, Object::new());
        let (back, rx) = b.subscribe(0);
        assert_eq!(back.len(), 1);
        b.publish("b", "info", None, Object::new());
        assert_eq!(rx.recv().unwrap().kind, "b");
        assert_eq!(b.since(1).len(), 1);
        drop(rx);
        b.publish("c", "info", None, Object::new());
        assert!(b.inner.lock().unwrap().subs.is_empty());
    }
}
