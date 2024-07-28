CREATE TABLE IF NOT EXISTS audit_records_selfservice
(
    id          bigserial  PRIMARY KEY,
    message_id  text       not null UNIQUE,
    type        text       not null,
    principal   text       not null,
    action      text       not null,
    method      text       not null,
    path        text       not null,
    service     text       not null,
    timestamp   timestamp  not null,
    created_at  timestamp  not null,
    request_data jsonb
);

CREATE UNIQUE INDEX audit_records_selfservice_id on audit_records_selfservice (id);
