use anyhow::anyhow;
use sqlx::{FromRow, PgPool, QueryBuilder};
use uuid::Uuid;

use crate::error::{LibError, Result};
use crate::models::{
    AuthChannel, AuthMode, CreateRoutePolicyDb, RoutePolicyDb, RoutePolicyListQuery,
    UpdateRoutePolicyDb, X402RequirementDb,
};

#[derive(Debug, Clone, FromRow)]
struct RoutePolicyRow {
    id: Uuid,
    method: String,
    path_pattern: String,
    mode: String,
    channels: serde_json::Value,
    facilitator_profile_id: Option<Uuid>,
    x402_accepts: serde_json::Value,
    active: bool,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

fn row_to_model(row: RoutePolicyRow) -> Result<RoutePolicyDb> {
    Ok(RoutePolicyDb {
        id: row.id,
        method: row.method,
        path_pattern: row.path_pattern,
        mode: parse_mode(&row.mode)?,
        channels: parse_channels(row.channels)?,
        facilitator_profile_id: row.facilitator_profile_id,
        x402_accepts: parse_accepts(row.x402_accepts)?,
        active: row.active,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn parse_mode(value: &str) -> Result<AuthMode> {
    match value {
        "any_of" => Ok(AuthMode::AnyOf),
        "all_of" => Ok(AuthMode::AllOf),
        _ => Err(LibError::database(
            "Failed to decode route policy mode",
            anyhow!("unknown auth mode: {value}"),
        )),
    }
}

fn mode_to_str(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::AnyOf => "any_of",
        AuthMode::AllOf => "all_of",
    }
}

fn parse_channels(value: serde_json::Value) -> Result<Vec<AuthChannel>> {
    serde_json::from_value(value).map_err(|err| {
        LibError::database(
            "Failed to decode route policy channels",
            anyhow!("parse_channels failed: {err}"),
        )
    })
}

fn parse_accepts(value: serde_json::Value) -> Result<Vec<X402RequirementDb>> {
    serde_json::from_value(value).map_err(|err| {
        LibError::database(
            "Failed to decode x402 accepts",
            anyhow!("parse_accepts failed: {err}"),
        )
    })
}

pub async fn create_route_policy(
    pool: &PgPool,
    payload: CreateRoutePolicyDb,
) -> Result<RoutePolicyDb> {
    let channels = serde_json::to_value(payload.channels).map_err(|err| {
        LibError::invalid(
            "Failed to encode policy channels",
            anyhow!("create_route_policy channels encode failed: {err}"),
        )
    })?;
    let x402_accepts = serde_json::to_value(payload.x402_accepts).map_err(|err| {
        LibError::invalid(
            "Failed to encode x402 accepts",
            anyhow!("create_route_policy x402_accepts encode failed: {err}"),
        )
    })?;

    let row = sqlx::query_as::<_, RoutePolicyRow>(
        r#"
        INSERT INTO x402.route_policies (
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING
            id,
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active,
            created_at,
            updated_at
        "#,
    )
    .bind(payload.method)
    .bind(payload.path_pattern)
    .bind(mode_to_str(payload.mode))
    .bind(channels)
    .bind(payload.facilitator_profile_id)
    .bind(x402_accepts)
    .bind(payload.active)
    .fetch_one(pool)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            LibError::conflict(
                "Route policy already exists for method + path pattern",
                anyhow!("create_route_policy unique violation: {err}"),
            )
        } else {
            LibError::database(
                "Failed to create route policy",
                anyhow!("create_route_policy failed: {err}"),
            )
        }
    })?;

    row_to_model(row)
}

pub async fn list_route_policies(
    pool: &PgPool,
    query: &RoutePolicyListQuery,
) -> Result<Vec<RoutePolicyDb>> {
    let (page, limit) = query.pagination();
    let offset: i64 = ((page - 1) as i64) * (limit as i64);

    let mut qb = QueryBuilder::new(
        r#"
        SELECT
            id,
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active,
            created_at,
            updated_at
        FROM x402.route_policies
        "#,
    );

    let mut has_where = false;
    if let Some(method) = query.method.as_ref() {
        qb.push(if has_where { " AND " } else { " WHERE " });
        has_where = true;
        qb.push("method = ").push_bind(method.to_ascii_uppercase());
    }
    if let Some(active) = query.active {
        qb.push(if has_where { " AND " } else { " WHERE " });
        qb.push("active = ").push_bind(active);
    }

    qb.push(" ORDER BY method ASC, path_pattern ASC LIMIT ")
        .push_bind(limit as i64)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows = qb
        .build_query_as::<RoutePolicyRow>()
        .fetch_all(pool)
        .await
        .map_err(|err| {
            LibError::database(
                "Failed to list route policies",
                anyhow!("list_route_policies failed: {err}"),
            )
        })?;

    rows.into_iter().map(row_to_model).collect()
}

pub async fn get_route_policy(pool: &PgPool, id: Uuid) -> Result<Option<RoutePolicyDb>> {
    let row = sqlx::query_as::<_, RoutePolicyRow>(
        r#"
        SELECT
            id,
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active,
            created_at,
            updated_at
        FROM x402.route_policies
        WHERE id = $1
        LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to get route policy",
            anyhow!("get_route_policy failed: {err}"),
        )
    })?;

    row.map(row_to_model).transpose()
}

pub async fn update_route_policy(
    pool: &PgPool,
    id: Uuid,
    patch: UpdateRoutePolicyDb,
) -> Result<Option<RoutePolicyDb>> {
    let existing = get_route_policy(pool, id).await?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    let merged = RoutePolicyDb {
        id: existing.id,
        method: existing.method,
        path_pattern: existing.path_pattern,
        mode: patch.mode.unwrap_or(existing.mode),
        channels: patch.channels.unwrap_or(existing.channels),
        facilitator_profile_id: patch
            .facilitator_profile_id
            .unwrap_or(existing.facilitator_profile_id),
        x402_accepts: patch.x402_accepts.unwrap_or(existing.x402_accepts),
        active: patch.active.unwrap_or(existing.active),
        created_at: existing.created_at,
        updated_at: existing.updated_at,
    };

    let channels = serde_json::to_value(merged.channels).map_err(|err| {
        LibError::invalid(
            "Failed to encode policy channels",
            anyhow!("update_route_policy channels encode failed: {err}"),
        )
    })?;
    let x402_accepts = serde_json::to_value(merged.x402_accepts).map_err(|err| {
        LibError::invalid(
            "Failed to encode x402 accepts",
            anyhow!("update_route_policy x402_accepts encode failed: {err}"),
        )
    })?;

    let row = sqlx::query_as::<_, RoutePolicyRow>(
        r#"
        UPDATE x402.route_policies
        SET
            mode = $2,
            channels = $3,
            facilitator_profile_id = $4,
            x402_accepts = $5,
            active = $6,
            updated_at = NOW()
        WHERE id = $1
        RETURNING
            id,
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active,
            created_at,
            updated_at
        "#,
    )
    .bind(id)
    .bind(mode_to_str(merged.mode))
    .bind(channels)
    .bind(merged.facilitator_profile_id)
    .bind(x402_accepts)
    .bind(merged.active)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to update route policy",
            anyhow!("update_route_policy failed: {err}"),
        )
    })?;

    row.map(row_to_model).transpose()
}

pub async fn delete_route_policy(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM x402.route_policies
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to delete route policy",
            anyhow!("delete_route_policy failed: {err}"),
        )
    })?;

    Ok(result.rows_affected() > 0)
}

pub async fn resolve_route_policy(
    pool: &PgPool,
    method: &str,
    path: &str,
) -> Result<Option<RoutePolicyDb>> {
    let method = method.trim().to_ascii_uppercase();
    let rows = sqlx::query_as::<_, RoutePolicyRow>(
        r#"
        SELECT
            id,
            method,
            path_pattern,
            mode,
            channels,
            facilitator_profile_id,
            x402_accepts,
            active,
            created_at,
            updated_at
        FROM x402.route_policies
        WHERE active = TRUE
          AND method = $1
        ORDER BY char_length(path_pattern) DESC
        "#,
    )
    .bind(method)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to resolve route policy",
            anyhow!("resolve_route_policy failed: {err}"),
        )
    })?;

    for row in rows {
        if path_pattern_matches(&row.path_pattern, path) {
            return row_to_model(row).map(Some);
        }
    }

    Ok(None)
}

pub fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = pattern.trim_end_matches('*');
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    let sqlx::Error::Database(db_err) = err else {
        return false;
    };
    db_err.code().as_deref() == Some("23505")
}

#[cfg(test)]
mod tests {
    use super::path_pattern_matches;

    #[test]
    fn wildcard_matches_prefix() {
        assert!(path_pattern_matches("/mcp/*", "/mcp/foo"));
        assert!(path_pattern_matches("/mcp/*", "/mcp/foo/bar"));
        assert!(!path_pattern_matches("/mcp/*", "/other/foo"));
    }

    #[test]
    fn exact_requires_full_match() {
        assert!(path_pattern_matches("/mcp/foo", "/mcp/foo"));
        assert!(!path_pattern_matches("/mcp/foo", "/mcp/foo/bar"));
    }
}
