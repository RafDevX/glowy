use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::{
    labels::{LabelBacktrace, SyntheticSlot},
    values::{FunctionRef, SelfAwareBacktraceContainer, Value, ValueCacheKey, ValueRef},
};

enum RealizationKind<'a, 'b> {
    Single {
        from_func: &'b FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&'b LabelBacktrace<'a>>,
    },
    Multiple {
        from_func: &'b FunctionRef<'a>,
        substitutions: &'b [(SyntheticSlot, Option<&'b LabelBacktrace<'a>>)],
    },
}

pub struct UnifiedRealization<'a, 'b> {
    kind: RealizationKind<'a, 'b>,
    value_cache: HashMap<ValueCacheKey, Rc<RefCell<Value<'a>>>>,
}

impl<'a, 'b> UnifiedRealization<'a, 'b> {
    pub fn single(
        from_func: &'b FunctionRef<'a>,
        from_slot: SyntheticSlot,
        concrete: Option<&'b LabelBacktrace<'a>>,
    ) -> Self {
        Self {
            kind: RealizationKind::Single {
                from_func,
                from_slot,
                concrete,
            },
            value_cache: HashMap::new(),
        }
    }

    pub fn multiple(
        from_func: &'b FunctionRef<'a>,
        substitutions: &'b [(SyntheticSlot, Option<&'b LabelBacktrace<'a>>)],
    ) -> Self {
        Self {
            kind: RealizationKind::Multiple {
                from_func,
                substitutions,
            },
            value_cache: HashMap::new(),
        }
    }

    pub fn dispatch(&self, backtrace: &LabelBacktrace<'a>) -> Option<LabelBacktrace<'a>> {
        match self.kind {
            RealizationKind::Single {
                from_func,
                from_slot,
                concrete,
            } => backtrace.realize(from_func, from_slot, concrete),
            RealizationKind::Multiple {
                from_func,
                substitutions,
            } => backtrace.realize_all(from_func, substitutions),
        }
    }

    pub(super) fn realize_with_cache(&mut self, target: &ValueRef<'a>) -> Rc<RefCell<Value<'a>>> {
        let cache_key = target.value_cache_key();

        if let Some(realized) = self.value_cache.get(&cache_key) {
            // already cached
            return Rc::clone(realized);
        }

        // seed the cache before descending so cycles can point at the same
        // realized allocation while it is being populated
        let realized = Rc::new(RefCell::new(Value::Simple(None)));
        self.value_cache.insert(cache_key, Rc::clone(&realized));

        *realized.borrow_mut() = target.value.borrow().realize_unified(self);

        realized
    }

    pub fn commits_channel_state(&self) -> bool {
        matches!(
            self.kind,
            RealizationKind::Single {
                from_slot: SyntheticSlot::CallSiteBranch,
                ..
            } | RealizationKind::Multiple { .. }
        )
    }
}
