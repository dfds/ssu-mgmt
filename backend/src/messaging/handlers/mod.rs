pub mod user_action;

use crate::messaging::handlers::user_action::user_action_handler;
use crate::messaging::registry::Registry;

pub fn register_handlers(registry : &mut Registry) {
    registry.register("user-action".to_owned(), user_action_handler);
}