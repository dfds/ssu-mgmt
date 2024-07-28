use std::sync::Arc;
use dashmap::DashMap;

#[derive(Clone)]
pub struct OffsetTracker {
    pub offsets: Arc<DashMap<i32, i64>>,
    pub active_partitions: Arc<DashMap<i32, i32>>
}

pub fn new_offset_tracker() -> OffsetTracker {
    return OffsetTracker {
        offsets: Arc::new(DashMap::new()),
        active_partitions: Arc::new(DashMap::new()),
    }
}