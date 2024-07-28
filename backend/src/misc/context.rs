use crossbeam::channel::{Receiver, Sender};
use crate::messaging::offset_tracker::OffsetTracker;
use crate::service::bg::Message;

#[derive(Clone)]
pub struct Context {
    pub offset_tracker : OffsetTracker,
    pub bg_sender : Sender<Message>,
    pub bg_receiver : Receiver<Message>,
}