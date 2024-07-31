use std::sync::Arc;
use crossbeam::channel::Sender;
use dashmap::DashMap;
use log::{debug, error, info, trace, warn};
use rdkafka::consumer::{BaseConsumer, CommitMode, Consumer, StreamConsumer};
use rdkafka::{Message, Offset, TopicPartitionList};
use rdkafka::error::KafkaResult;
use rdkafka::message::Headers;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use crate::messaging::consumer::CustomConsumerContext;
use crate::messaging::handlers::register_handlers;
use crate::messaging::model::{Context, Envelope};
use crate::messaging::offset_tracker::OffsetTracker;
use crate::messaging::registry::{new_registry, Registry};
use crate::misc;
use crate::misc::error::SsuResult;
use crate::misc::services::ServicesShared;

pub mod consumer;
pub mod config;
pub mod model;
pub mod registry;
pub mod handlers;
pub mod offset_tracker;

pub const SS_CONTEXT_NAME : &str = "MESSAGING_CONTEXT";

pub async fn start_messaging(ct : CancellationToken, ss: ServicesShared) -> SsuResult<()> {
    let context = ss.read().unwrap().get_named_service_clone::<misc::context::Context>(SS_CONTEXT_NAME).unwrap();
    let mut registry = new_registry();
    register_handlers(&mut registry);
    let m_consumer = consumer::create_consumer_base(context.offset_tracker.clone())?;
    m_consumer.subscribe(&["cloudengineering.selfservice.audit"])?;

    // tokio::spawn(consumer_loop(m_consumer, ct.clone(), context.clone(), registry));
    // tokio::spawn(offset_updater(ct.clone(), context.offset_tracker.clone()));

    std::thread::spawn(move || {
       consumer_loop_base(m_consumer, ct.clone(), context.clone(), registry);
    });

    Ok(())
}

fn consumer_loop_base(consumer : BaseConsumer<CustomConsumerContext>, ct : CancellationToken, context: misc::context::Context, registry: Registry) {
    let mut last_offset_update_time = chrono::Utc::now().naive_utc();

    loop {
        if ct.is_cancelled() {
            info!("Stopping consumer loop");
            break;
        }

        let poll_resp = consumer.poll(rdkafka::util::Timeout::After(std::time::Duration::from_secs(1)));
        match poll_resp {
            None => {
                // update offsets if a certain amount of time has passed
                let time_now = chrono::Utc::now().naive_utc();
                if time_now.signed_duration_since(last_offset_update_time).num_seconds() >= 30 {
                    trace!("Updating offsets");
                    trace!("offset tracker stats");
                    for x in context.offset_tracker.offsets.as_ref() {
                        trace!("partition: {} -> offset: {}", x.key(), x.value());
                    }
                    if context.offset_tracker.offsets.len() > 0 {
                        let mut tpl = TopicPartitionList::new();
                        for x in context.offset_tracker.offsets.as_ref() {
                            tpl.add_partition("cloudengineering.selfservice.audit", *x.key());
                            tpl.set_partition_offset("cloudengineering.selfservice.audit", *x.key(), Offset::Offset(*x.value()));
                        }

                        consumer.commit(&tpl, CommitMode::Sync).unwrap_or_else(|err| {
                            error!("{:?}", err);
                            ()
                        });
                    }
                    last_offset_update_time = chrono::Utc::now().naive_utc();
                }
            }
            Some(msg) => {
                match msg {
                    Err(e) => warn!("Kafka error: {}", e),
                    Ok(m) => {
                        let payload = match m.payload_view::<str>() {
                            None => "",
                            Some(Ok(s)) => s,
                            Some(Err(e)) => {
                                warn!("Error while deserializing message payload: {:?}", e);
                                ""
                            }
                        };
                        // trace!("key: '{:?}', payload: '{}', topic: {}, partition: {}, offset: {}, timestamp: {:?}",
                        //       m.key(), payload, m.topic(), m.partition(), m.offset(), m.timestamp());
                        if let Some(headers) = m.headers() {
                            for header in headers.iter() {
                                trace!("  Header {:#?}: {:?}", header.key, header.value);
                            }
                        }

                        let envelope : SsuResult<Envelope> = serde_json::from_str(payload).map_err(|e| e.into());
                        match envelope {
                            Ok(data) => {
                                // handle msg
                                match registry.get_handler(&data._type) {
                                    None => {
                                        debug!("No handler registered for event type {}, skipping", &data._type);
                                    },
                                    Some(handler) => {
                                        let resp = handler(Context {
                                            event: data.clone(),
                                            msg: payload.to_owned(),
                                            context: context.clone()
                                        }
                                        );

                                        if let Err(e) = resp {
                                            error!("{:?}", e);
                                        }
                                    }}
                            }
                            Err(_) => {
                                error!("Unknown message format, skipping")
                            }
                        }

                        // update offset tracker
                        context.offset_tracker.offsets.insert(m.partition(), m.offset() + 1);
                    }
                };
            }
        }
    }
}

async fn consumer_loop(consumer : StreamConsumer<CustomConsumerContext>, ct : CancellationToken, context: misc::context::Context, registry: Registry) {
    loop {
        tokio::select! {
            _ = ct.cancelled() => {
                info!("Stopping consumer loop");
                break;
            }
            resp = consumer.recv() => {
                match resp {
                    Err(e) => warn!("Kafka error: {}", e),
                    Ok(m) => {
                        let payload = match m.payload_view::<str>() {
                            None => "",
                            Some(Ok(s)) => s,
                            Some(Err(e)) => {
                                warn!("Error while deserializing message payload: {:?}", e);
                                ""
                            }
                        };
                        // trace!("key: '{:?}', payload: '{}', topic: {}, partition: {}, offset: {}, timestamp: {:?}",
                        //       m.key(), payload, m.topic(), m.partition(), m.offset(), m.timestamp());
                        if let Some(headers) = m.headers() {
                            for header in headers.iter() {
                                trace!("  Header {:#?}: {:?}", header.key, header.value);
                            }
                        }

                        let envelope : SsuResult<Envelope> = serde_json::from_str(payload).map_err(|e| e.into());
                        match envelope {
                            Ok(data) => {
                                // handle msg
                                match registry.get_handler(&data._type) {
                                    None => {
                                        debug!("No handler registered for event type {}, skipping", &data._type);
                                    },
                                    Some(handler) => {
                                        let resp = handler(Context {
                                            event: data.clone(),
                                            msg: payload.to_owned(),
                                            context: context.clone()
                                        }
                                        );

                                        if let Err(e) = resp {
                                            error!("{:?}", e);
                                        }
                                    }}
                            }
                            Err(_) => {
                                error!("Unknown message format, skipping")
                            }
                        }

                        // update offset tracker
                        context.offset_tracker.offsets.insert(m.partition(), m.offset() + 1);
                    }
                };

            }
        }
    }
}