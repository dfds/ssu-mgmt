use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub enum Bind {
    Text(String),
    Double(f64),
    BigInt(i64),
    TextArray(Vec<String>),
    Ts(DateTime<Utc>),
}

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Node {
    Group {
        op: BoolOp,
        children: Vec<Node>,
    },
    Not {
        child: Box<Node>,
    },
    Field {
        field: Field,
        op: Op,
        value: String,
    },
    Ts {
        op: Op,
        value: String,
    },
    JsonPath {
        path: Vec<String>,
        op: Op,
        value: String,
        value_type: ValueType,
    },
    Raw {
        value: String,
    },
}

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum BoolOp {
    And,
    Or,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Contains,
    NotContains,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Text,
    Number,
}

/// The 10 normalized columns on the `ssumgmt_events` view. Tags are lowercased
/// to match the frontend `EventField` names (`ip`, `idsource`).
#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Actor,
    Source,
    Action,
    Resource,
    Ip,
    Status,
    Level,
    Uid,
    Role,
    IdSource,
    Account,
    CallerAccount,
}

impl Field {
    fn column(self) -> &'static str {
        match self {
            Field::Actor => "actor",
            Field::Source => "source",
            Field::Action => "action",
            Field::Resource => "resource",
            Field::Ip => "source_ip",
            Field::Status => "status",
            Field::Level => "level",
            Field::Uid => "uid",
            Field::Role => "role",
            Field::IdSource => "identity_source",
            Field::Account => "account_id",
            Field::CallerAccount => "caller_account_id",
        }
    }
}

/// Parse an RFC3339 (or naive `%Y-%m-%dT%H:%M:%S`) timestamp. Shared by the AST
/// `Ts` node and the `from`/`to` facets.
pub fn parse_ts(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .map(|n| DateTime::from_naive_utc_and_offset(n, Utc))
        })
        .or_else(|_| {
            // Allow a bare date (`2026-06-20`) — common in `ts >= 2026-06-20`.
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map(|d| DateTime::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0).unwrap(), Utc))
        })
        .map_err(|e| format!("invalid timestamp {}: {}", s, e))
}

pub fn compile(node: &Node, binds: &mut Vec<Bind>) -> Result<String, String> {
    match node {
        Node::Group { op, children } => {
            if children.is_empty() {
                return Ok("TRUE".to_string());
            }
            let joiner = match op {
                BoolOp::And => " AND ",
                BoolOp::Or => " OR ",
            };
            let parts = children
                .iter()
                .map(|c| compile(c, binds))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("({})", parts.join(joiner)))
        }
        Node::Not { child } => Ok(format!("NOT ({})", compile(child, binds)?)),
        Node::Field { field, op, value } => compile_field(*field, *op, value, binds),
        Node::Ts { op, value } => compile_ts(*op, value, binds),
        Node::JsonPath {
            path,
            op,
            value,
            value_type,
        } => compile_jsonpath(path, *op, value, *value_type, binds),
        Node::Raw { value } => {
            binds.push(Bind::Text(format!("%{}%", value)));
            Ok(format!("(raw::text ILIKE ${})", binds.len()))
        }
    }
}

fn compile_field(
    field: Field,
    op: Op,
    value: &str,
    binds: &mut Vec<Bind>,
) -> Result<String, String> {
    let col = field.column();
    match op {
        Op::Eq => {
            binds.push(Bind::Text(value.to_owned()));
            Ok(format!("{} = ${}", col, binds.len()))
        }
        Op::Ne => {
            binds.push(Bind::Text(value.to_owned()));
            Ok(format!("{} IS DISTINCT FROM ${}", col, binds.len()))
        }
        Op::Contains => {
            binds.push(Bind::Text(format!("%{}%", value)));
            Ok(format!("{} ILIKE ${}", col, binds.len()))
        }
        Op::NotContains => {
            binds.push(Bind::Text(format!("%{}%", value)));
            Ok(format!(
                "({} IS NULL OR {} NOT ILIKE ${})",
                col,
                col,
                binds.len()
            ))
        }
        _ => Err(format!(
            "comparison operators are not allowed on field `{}`",
            col
        )),
    }
}

fn compile_ts(op: Op, value: &str, binds: &mut Vec<Bind>) -> Result<String, String> {
    let ts = parse_ts(value)?;
    let sql_op = comparison_op(op).ok_or("operator not allowed on `ts`")?;
    binds.push(Bind::Ts(ts));
    Ok(format!("ts {} ${}", sql_op, binds.len()))
}

fn compile_jsonpath(
    path: &[String],
    op: Op,
    value: &str,
    vt: ValueType,
    binds: &mut Vec<Bind>,
) -> Result<String, String> {
    if path.is_empty() {
        return Err("empty json path".to_string());
    }
    binds.push(Bind::TextArray(path.to_vec()));
    let p = binds.len();
    match vt {
        ValueType::Text => match op {
            Op::Eq => {
                binds.push(Bind::Text(value.to_owned()));
                Ok(format!("(raw #>> ${}) = ${}", p, binds.len()))
            }
            Op::Ne => {
                binds.push(Bind::Text(value.to_owned()));
                Ok(format!(
                    "(raw #>> ${}) IS DISTINCT FROM ${}",
                    p,
                    binds.len()
                ))
            }
            Op::Contains => {
                binds.push(Bind::Text(format!("%{}%", value)));
                Ok(format!("(raw #>> ${}) ILIKE ${}", p, binds.len()))
            }
            Op::NotContains => {
                binds.push(Bind::Text(format!("%{}%", value)));
                Ok(format!(
                    "((raw #>> ${p}) IS NULL OR (raw #>> ${p}) NOT ILIKE ${v})",
                    p = p,
                    v = binds.len()
                ))
            }
            _ => Err("comparison operators require a numeric json path".to_string()),
        },
        ValueType::Number => {
            let num: f64 = value
                .parse()
                .map_err(|_| format!("`{}` is not a number", value))?;
            let sql_op = match op {
                Op::Eq => "=",
                Op::Ne => "<>",
                _ => comparison_op(op).ok_or("operator not allowed on json path")?,
            };
            binds.push(Bind::Double(num));
            Ok(format!(
                "((raw #>> ${p}) ~ '^-?[0-9.]+$' AND (raw #>> ${p})::numeric {op} ${v}::numeric)",
                p = p,
                op = sql_op,
                v = binds.len()
            ))
        }
    }
}

/// The SQL spelling of a comparison/equality operator, or None for the
/// substring operators that don't apply to ordered values.
fn comparison_op(op: Op) -> Option<&'static str> {
    match op {
        Op::Eq => Some("="),
        Op::Ne => Some("<>"),
        Op::Gt => Some(">"),
        Op::Gte => Some(">="),
        Op::Lt => Some("<"),
        Op::Lte => Some("<="),
        Op::Contains | Op::NotContains => None,
    }
}
