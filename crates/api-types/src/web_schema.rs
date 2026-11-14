use schemars::{SchemaGenerator, generate::SchemaSettings};
use serde_json::{Value, json};

use crate::spec::ServiceSpec;

/// 页面用到的序列化类型的 JSON Schema。
pub fn web_schema() -> Value {
  let mut generator =
    SchemaGenerator::new(SchemaSettings::default().for_serialize());
  let _ = generator.subschema_for::<ServiceSpec>();
  json!({ "$defs": generator.take_definitions(true) })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn service_required_fields() {
    let schema = web_schema();
    let service = &schema["$defs"]["ServiceSpec"];
    let mut required: Vec<_> = service["required"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap())
      .collect();
    required.sort_unstable();
    assert_eq!(required, ["server", "source"]);
  }
}
