use std::collections::HashMap;
use std::sync::Arc;
use crate::messaging::model::{Context, Envelope};
use crate::messaging::offset_tracker::OffsetTracker;
use crate::misc::error::SsuResult;

pub struct Registry {
    handlers : HashMap<String, Handler>
}

impl Registry {
    pub fn register<F : Fn(Context) -> SsuResult<()> +'static + Send + Sync>(&mut self, event_name : String, handler : F) {
        self.handlers.insert(event_name.clone(), Handler {
            name: event_name.clone(),
            description: "".to_owned(),
            handler_func: Arc::new(handler),
        });
    }

    pub fn get_handler(&self, event_name : &str) -> Option<HandlerFuncArc> {
        match self.handlers.get(event_name) {
            None => None,
            Some(handler) => Some(handler.handler_func.clone())
        }
    }
}

pub fn new_registry() -> Registry {
    Registry {
        handlers: HashMap::new()
    }
}

type HandlerFunc = dyn Fn(Context) -> SsuResult<()> + Send + Sync;
type HandlerFuncArc = Arc<HandlerFunc>;

#[derive(Clone)]
pub struct Handler {
    pub name : String,
    pub description : String,
    pub handler_func : HandlerFuncArc,
}

pub fn playground() {
    let mut registry = new_registry();
    let (s, r) = crossbeam::channel::unbounded();
    (registry.handlers["wowza"].handler_func)(Context {
        event: Envelope {
            _type: "".to_string(),
            message_id: "".to_string(),
        },
        msg: "".to_string(),
        context: crate::misc::context::Context {
            offset_tracker: OffsetTracker { offsets: Arc::new(Default::default()), active_partitions: Arc::new(Default::default()) },
            bg_sender: s,
            bg_receiver: r,
        },
    }).expect("TODO: panic message");
}