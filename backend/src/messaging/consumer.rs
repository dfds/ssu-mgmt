use futures::{FutureExt, TryFutureExt};
use log::{debug, info, trace, warn};
use rdkafka::{ClientConfig, ClientContext, Message, TopicPartitionList};
use rdkafka::config::RDKafkaLogLevel;
use rdkafka::consumer::{ConsumerContext, BaseConsumer, Rebalance, StreamConsumer, Consumer, CommitMode};
use rdkafka::error::KafkaResult;
use rdkafka::message::Headers;
use crate::messaging::config::MessagingConfig;
use crate::messaging::handlers::register_handlers;
use crate::messaging::offset_tracker::OffsetTracker;
use crate::messaging::registry::new_registry;
use crate::misc::config::load_conf;
use crate::misc::error::SsuResult;

pub struct CustomConsumerContext {
    offset_tracker: OffsetTracker
}

impl ClientContext for CustomConsumerContext {}

impl ConsumerContext for CustomConsumerContext {
    fn pre_rebalance(&self, rebalance: &Rebalance) {
        trace!("Pre rebalance {:?}", rebalance);
    }

    fn post_rebalance(&self, rebalance: &Rebalance) {
        match rebalance {
            Rebalance::Assign(data) => {
                for topic in data.elements() {
                    info!("Assigned partition {} for topic {}", topic.partition(), topic.topic());
                    self.offset_tracker.active_partitions.insert(topic.partition(), 1);
                }
            }
            Rebalance::Revoke(data) => {
                for topic in data.elements() {
                    info!("Unassigned partition {} for topic {}", topic.partition(), topic.topic());
                    self.offset_tracker.active_partitions.remove(&topic.partition());
                }
            }
            Rebalance::Error(err) => {
                trace!("Post rebalance error {:?}", err);
            }
        }
    }

    fn commit_callback(&self, result: KafkaResult<()>, _offsets: &TopicPartitionList) {
        trace!("Committing offsets: {:?}", result);
    }
}

pub fn create_consumer(offset_tracker : OffsetTracker) -> SsuResult<StreamConsumer<CustomConsumerContext>> {
    let context = CustomConsumerContext {offset_tracker};
    let conf = load_conf().unwrap();
    create_client_config(&conf.messaging)
        .create_with_context(context).map_err(|e| e.into())
}

pub fn create_consumer_base(offset_tracker: OffsetTracker) -> SsuResult<BaseConsumer<CustomConsumerContext>> {
    let context = CustomConsumerContext {offset_tracker};
    let conf = load_conf().unwrap();
    create_client_config(&conf.messaging)
        .create_with_context(context).map_err(|e| e.into())
}

pub fn create_client_config(conf : &MessagingConfig) -> ClientConfig {
    let mut payload = ClientConfig::new();
        payload
        .set("group.id", &conf.group_id)
        .set("client.id", "ssu-mgmt")
        .set("bootstrap.servers", &conf.bootstrap_servers)
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("sasl.mechanism", &conf.sasl_mechanism)
        .set("security.protocol", &conf.security_protocol)
        .set("sasl.username", &conf.credentials.username)
        .set("sasl.password", &conf.credentials.password)
        .set_log_level(RDKafkaLogLevel::Debug);

        payload
}