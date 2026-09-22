// Dependency ordering adapted from Chromium's Http2PriorityDependencies.
// Copyright 2016 The Chromium Authors. BSD license: see CHROMIUM-LICENSE.
// Source revision: 3188f8a607ae7e067593be8aab7f02d2451fec07.

use super::{Inner, Store, StreamId, UserError};
use parking_lot::{Mutex, MutexGuard};
use rama_core::extensions::Extension;
use rama_http_types::proto::h2::frame::{Priority, StreamDependency};
use std::sync::{Arc, Weak};

/// Opt a request into an exclusive dependency chain ordered by encoded weight.
///
/// Larger weights are higher priority. A request depends on the latest live
/// stream in the nearest weight band at or above its own. Equal-weight streams
/// retain their opening order. Requests without this extension are unchanged.
/// Clones share one control; use a distinct control for each concurrent request.
#[derive(Clone, Debug)]
pub struct RequestPriority {
    state: Arc<Mutex<ControlState>>,
}

#[derive(Debug)]
pub(super) struct ControlState {
    pub(super) weight: u8,
    binding: Option<Binding>,
}

#[derive(Debug)]
struct Binding {
    connection: Weak<Mutex<Inner>>,
    id: StreamId,
}

impl Extension for RequestPriority {}

impl RequestPriority {
    /// Create a priority using the HTTP/2 encoded weight range `0..=255`.
    #[must_use]
    pub fn new(weight: u8) -> Self {
        Self {
            state: Arc::new(Mutex::new(ControlState {
                weight,
                binding: None,
            })),
        }
    }

    /// The encoded HTTP/2 weight, one less than the RFC 7540 weight (1..=256).
    #[must_use]
    pub fn weight(&self) -> u8 {
        self.state.lock().weight
    }

    /// Change this request's priority synchronously, including an active stream.
    /// Before its first HEADERS, only the initial priority changes. After stream
    /// closure the value is retained for a subsequent retry or redirect.
    pub fn set_weight(&self, weight: u8) {
        let mut state = self.state.lock();
        state.weight = weight;
        if let Some(binding) = &state.binding
            && let Some(connection) = binding.connection.upgrade()
        {
            let mut connection = connection.lock();
            connection.store.change_priority(binding.id, weight);
            if let Some(task) = connection.actions.task.take() {
                task.wake();
            }
        }
    }

    // Always lock control before connection. The protocol driver never takes
    // the control lock. Inspect an old binding before locking a new connection.
    pub(super) fn for_request(&self) -> Result<MutexGuard<'_, ControlState>, UserError> {
        let state = self.state.lock();
        if let Some(binding) = &state.binding
            && let Some(connection) = binding.connection.upgrade()
            && connection
                .lock()
                .store
                .find_mut(binding.id)
                .is_some_and(|stream| !stream.state.is_closed())
        {
            return Err(UserError::Rejected);
        }
        Ok(state)
    }
}

impl ControlState {
    pub(super) fn bind(&mut self, connection: &Arc<Mutex<Inner>>, id: StreamId) {
        self.binding = Some(Binding {
            connection: Arc::downgrade(connection),
            id,
        });
    }
}

impl Store {
    /// Opening is recorded only when the initial HEADERS enter the codec.
    pub(crate) fn open_priority(&mut self, id: StreamId) -> Option<StreamDependency> {
        let weight = self.find_mut(id)?.request_priority?;
        self.prune_priorities();
        let position = self
            .priority_order
            .partition_point(|(_, band)| *band >= weight);
        let parent = position
            .checked_sub(1)
            .map_or(StreamId::zero(), |index| self.priority_order[index].0);
        self.priority_order.insert(position, (id, weight));
        Some(StreamDependency::new(parent, weight, true))
    }

    fn change_priority(&mut self, id: StreamId, weight: u8) {
        let Some(mut stream) = self.find_mut(id) else {
            return;
        };
        if stream.state.is_closed() || stream.request_priority == Some(weight) {
            return;
        }
        stream.request_priority = Some(weight);
        self.prune_priorities();
        let Some(old) = self.priority_order.iter().position(|entry| entry.0 == id) else {
            return; // Not yet emitted: the initial HEADERS will read the new weight.
        };
        let old_parent = self.parent_at(old);
        let new_position = self
            .priority_order
            .partition_point(|(_, band)| *band >= weight);
        let mut new_parent = self.parent_at(new_position);
        if new_parent == id {
            new_parent = old_parent;
        }
        if old_parent != new_parent {
            if let Some(&(child, child_weight)) = self.priority_order.get(old + 1) {
                self.priority_updates.push_back(Priority::new(
                    child,
                    StreamDependency::new(old_parent, child_weight, true),
                ));
            }
            self.priority_updates.push_back(Priority::new(
                id,
                StreamDependency::new(new_parent, weight, true),
            ));
        }
        self.priority_order.remove(old);
        let position = self
            .priority_order
            .partition_point(|(_, band)| *band >= weight);
        self.priority_order.insert(position, (id, weight));
    }

    fn parent_at(&self, position: usize) -> StreamId {
        position
            .checked_sub(1)
            .map_or(StreamId::zero(), |index| self.priority_order[index].0)
    }

    fn prune_priorities(&mut self) {
        let mut order = std::mem::take(&mut self.priority_order);
        order.retain(|(id, _)| {
            self.find_mut(*id)
                .is_some_and(|stream| !stream.state.is_closed())
        });
        self.priority_order = order;
    }
}
