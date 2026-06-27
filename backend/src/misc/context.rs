use crate::messaging::offset_tracker::OffsetTracker;
use crate::service::bg::Message;
use crossbeam::channel::{Receiver, Sender};

#[derive(Clone)]
pub struct Context {
    pub offset_tracker: OffsetTracker,
    pub bg_sender: Sender<Message>,
    pub bg_receiver: Receiver<Message>,
}
