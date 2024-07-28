use std::sync::Arc;
use crossbeam::channel::{Receiver, RecvError, RecvTimeoutError, Sender};
use dashmap::DashMap;
use diesel::RunQueryDsl;
use log::{error, info};
use seqtf_bootstrap::shutdown::Shutdown;
use crate::db::model::AuditRecordsSelfserviceInsert;
use crate::messaging::handlers::user_action::UserActionMessage;
use crate::messaging::model::EnvelopeWithPayload;
use crate::messaging::offset_tracker::OffsetTracker;
use crate::misc::config::load_conf;

#[derive(Debug)]
pub enum Message {
    UserAction(EnvelopeWithPayload<UserActionMessage>)
}

pub fn start(shutdown: Shutdown, sender: Sender<Message>, receiver: Receiver<Message>, offset_tracker: OffsetTracker) {
    // msg receiver
    std::thread::spawn(move || {
        let mut insert_buffer : Vec<EnvelopeWithPayload<UserActionMessage>> = Vec::new();
        let mut last_insert_time = chrono::Utc::now().naive_utc();
        loop {
            // process incoming
            match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(msg) => {
                    match msg {
                        Message::UserAction(msg) => {
                            insert_buffer.push(msg);
                        }
                    }
                }
                Err(err) => {
                    let mut continue_shutdown = true;
                    if let RecvTimeoutError::Timeout = err {
                        continue_shutdown = false
                    }

                    if continue_shutdown {
                        error!("{:?}", err);
                        shutdown.exit.trigger_shutdown();
                        break;
                    }
                }
            }

            // check if conditions for inserting buffer has been met
            let time_now = chrono::Utc::now().naive_utc();
            if time_now.signed_duration_since(last_insert_time).num_seconds() > 5 && insert_buffer.len() > 0 {
                let insert_payload = insert_buffer;
                insert_buffer = Vec::new();

                info!("Current insert buffer: {}", insert_payload.len());

                std::thread::spawn(move || {
                    let conf = load_conf().unwrap();
                    let mut db_conn = crate::db::get_db_conn(&conf.db).unwrap();
                    let mut payload: Vec<AuditRecordsSelfserviceInsert> = insert_payload.into_iter().map(|envelope| {
                        let request_data = {
                            if envelope.data.request_data != "" {
                                Some(envelope.data.request_data)
                            } else {
                                None
                            }
                        };


                        AuditRecordsSelfserviceInsert {
                            message_id: envelope.message_id,
                            created_at: chrono::Utc::now().naive_utc(),
                            timestamp: chrono::DateTime::from_timestamp(envelope.data.timestamp, 0).unwrap().naive_utc(),
                            record_type: envelope._type,
                            principal: envelope.data.username,
                            action: envelope.data.action,
                            method: envelope.data.method,
                            path: envelope.data.path,
                            service: envelope.data.service,
                            request_data: request_data,
                        }
                    }).collect();

                    let chunks : Vec<Vec<AuditRecordsSelfserviceInsert>> = payload.chunks(4000)
                        .map(|c| c.to_vec())
                        .collect();

                    for chunk in chunks {
                        diesel::insert_into(crate::schema::audit_records_selfservice::table)
                            .values(&chunk)
                            .on_conflict_do_nothing() // if row already exists, just ignore it
                            .execute(&mut db_conn).unwrap();
                    }
                });
                last_insert_time = chrono::Utc::now().naive_utc();
            }



            if !shutdown.exit.proceed() {
                info!("Stopping bg service");
                break
            }
        }
    });

    // update offset
    std::thread::spawn(move || {

    });
}