// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022-2023 The crypto-auditing developers.

use crate::types::{Context, ContextId, Event, EventGroup};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tracing::info;

#[derive(Debug)]
pub struct ContextTracker {
    all_contexts: Vec<Rc<RefCell<Context>>>,
    root_contexts: Vec<Rc<RefCell<Context>>>,
    larval_contexts: HashMap<ContextId, Rc<RefCell<Context>>>,
    parents: HashMap<ContextId, ContextId>,
    boot_time: SystemTime,
}

impl ContextTracker {
    pub fn new(boot_time: Option<SystemTime>) -> Self {
        Self {
            all_contexts: Vec::new(),
            root_contexts: Vec::new(),
            larval_contexts: HashMap::new(),
            parents: HashMap::new(),
            boot_time: boot_time.unwrap_or_else(|| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(System::boot_time()))
                    .unwrap()
            }),
        }
    }

    pub fn flush(&mut self, before: Option<SystemTime>) -> impl IntoIterator<Item = Context> {
        let mut removed = Vec::new();
        let not_expired = |context: &Rc<RefCell<Context>>| matches!(before, Some(before) if context.borrow().start > before);
        self.root_contexts.retain(|context| {
            if not_expired(context) {
                true
            } else {
                removed.push(context.clone());
                false
            }
        });
        self.all_contexts.retain(|context| not_expired(context));
        removed
            .into_iter()
            .map(|context| Rc::into_inner(context).unwrap().into_inner())
    }

    fn push_orphaned_context(&mut self, id: &ContextId, start: SystemTime, end: SystemTime) {
        let context = Rc::new(RefCell::new(Context {
            id: *id,
            start,
            end,
            ..Default::default()
        }));
        self.root_contexts.push(context.clone());
        self.all_contexts.push(context);
    }

    fn last_context(&self, id: &ContextId) -> Option<&Rc<RefCell<Context>>> {
        self.all_contexts
            .iter()
            .rev()
            .find(|context| context.borrow().id == *id)
    }

    fn resolve_system_time(&self, time: Duration) -> SystemTime {
        self.boot_time.checked_add(time).unwrap_or(UNIX_EPOCH)
    }

    // Returns `true` if a root context is created
    fn handle_event(
        &mut self,
        id: &ContextId,
        start: SystemTime,
        end: SystemTime,
        event: &Event,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match event {
            Event::NewContext {
                parent: parent_context,
                origin,
                executable,
            } => {
                let larval_context = Rc::new(RefCell::new(Context {
                    id: *id,
                    origin: origin.to_owned(),
                    executable: executable.to_owned(),
                    start,
                    end,
                    ..Default::default()
                }));
                self.larval_contexts.insert(*id, larval_context);
                self.parents.insert(*id, *parent_context);
                Ok(false)
            }
            Event::Data { key, value } if key == "name" => {
                if let Some(larval_context) = self.larval_contexts.remove(id) {
                    larval_context
                        .borrow_mut()
                        .events
                        .insert(key.to_string(), value.clone());
                    if let Some(parent_context) = self.parents.remove(id)
                        && let Some(parent) = self.last_context(&parent_context)
                    {
                        parent.borrow_mut().spans.push(larval_context.clone());
                        self.all_contexts.push(larval_context);
                        Ok(false)
                    } else {
                        self.root_contexts.push(larval_context.clone());
                        self.all_contexts.push(larval_context);
                        Ok(true)
                    }
                } else {
                    self.push_orphaned_context(id, start, end);
                    Ok(true)
                }
            }
            Event::Data { key, value } => {
                if let Some(context) = self.last_context(id) {
                    context
                        .borrow_mut()
                        .events
                        .insert(key.to_string(), value.clone());
                    Ok(false)
                } else {
                    self.push_orphaned_context(id, start, end);
                    Ok(true)
                }
            }
        }
    }

    /// Returns the number of root contexts created from `group`
    pub fn handle_event_group(&mut self, group: &EventGroup) -> usize {
        let start = self.resolve_system_time(group.start());
        let end = self.resolve_system_time(group.end());
        let mut count = 0;
        for event in group.events() {
            match self.handle_event(group.context(), start, end, event) {
                Ok(res) => {
                    if res {
                        count += 1;
                    }
                }
                Err(e) => info!(error = %e, "error while handling event {:#?}",
                                event),
            }
        }
        count
    }
}
