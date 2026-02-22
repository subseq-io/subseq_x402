use std::collections::HashMap;

use anyhow::anyhow;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{LibError, Result};
use crate::models::{CreateFacilitatorProfileDb, FacilitatorProfileDb, UpdateFacilitatorProfileDb};

#[derive(Debug, Clone, FromRow)]
struct FacilitatorProfileRow {
    id: Uuid,
    name: String,
    verify_url: String,
    settle_url: String,
    supported_url: String,
    default_headers: serde_json::Value,
    timeout_ms: i32,
    supported_cache_ttl_secs: i32,
    enabled: bool,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

fn row_to_model(row: FacilitatorProfileRow) -> Result<FacilitatorProfileDb> {
    let default_headers: HashMap<String, String> = serde_json::from_value(row.default_headers)
        .map_err(|err| {
            LibError::database(
                "Failed to decode facilitator profile headers",
                anyhow!("row_to_model default_headers decode failed: {err}"),
            )
        })?;

    Ok(FacilitatorProfileDb {
        id: row.id,
        name: row.name,
        verify_url: row.verify_url,
        settle_url: row.settle_url,
        supported_url: row.supported_url,
        default_headers,
        timeout_ms: row.timeout_ms,
        supported_cache_ttl_secs: row.supported_cache_ttl_secs,
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

pub async fn create_facilitator_profile(
    pool: &PgPool,
    payload: CreateFacilitatorProfileDb,
) -> Result<FacilitatorProfileDb> {
    let default_headers = serde_json::to_value(payload.default_headers).map_err(|err| {
        LibError::invalid(
            "Failed to encode facilitator headers",
            anyhow!("create_facilitator_profile default_headers encode failed: {err}"),
        )
    })?;

    let row = sqlx::query_as::<_, FacilitatorProfileRow>(
        r#"
        INSERT INTO x402.facilitator_profiles (
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING
            id,
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled,
            created_at,
            updated_at
        "#,
    )
    .bind(payload.name)
    .bind(payload.verify_url)
    .bind(payload.settle_url)
    .bind(payload.supported_url)
    .bind(default_headers)
    .bind(payload.timeout_ms)
    .bind(payload.supported_cache_ttl_secs)
    .bind(payload.enabled)
    .fetch_one(pool)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            LibError::conflict(
                "Facilitator profile name already exists",
                anyhow!("create_facilitator_profile unique violation: {err}"),
            )
        } else {
            LibError::database(
                "Failed to create facilitator profile",
                anyhow!("create_facilitator_profile failed: {err}"),
            )
        }
    })?;

    row_to_model(row)
}

pub async fn list_facilitator_profiles(pool: &PgPool) -> Result<Vec<FacilitatorProfileDb>> {
    let rows = sqlx::query_as::<_, FacilitatorProfileRow>(
        r#"
        SELECT
            id,
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled,
            created_at,
            updated_at
        FROM x402.facilitator_profiles
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to list facilitator profiles",
            anyhow!("list_facilitator_profiles failed: {err}"),
        )
    })?;

    rows.into_iter().map(row_to_model).collect()
}

pub async fn get_facilitator_profile(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<FacilitatorProfileDb>> {
    let row = sqlx::query_as::<_, FacilitatorProfileRow>(
        r#"
        SELECT
            id,
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled,
            created_at,
            updated_at
        FROM x402.facilitator_profiles
        WHERE id = $1
        LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to get facilitator profile",
            anyhow!("get_facilitator_profile failed: {err}"),
        )
    })?;

    row.map(row_to_model).transpose()
}

pub async fn update_facilitator_profile(
    pool: &PgPool,
    id: Uuid,
    patch: UpdateFacilitatorProfileDb,
) -> Result<Option<FacilitatorProfileDb>> {
    let existing = get_facilitator_profile(pool, id).await?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    let merged = CreateFacilitatorProfileDb {
        name: patch.name.unwrap_or(existing.name),
        verify_url: patch.verify_url.unwrap_or(existing.verify_url),
        settle_url: patch.settle_url.unwrap_or(existing.settle_url),
        supported_url: patch.supported_url.unwrap_or(existing.supported_url),
        default_headers: patch.default_headers.unwrap_or(existing.default_headers),
        timeout_ms: patch.timeout_ms.unwrap_or(existing.timeout_ms),
        supported_cache_ttl_secs: patch
            .supported_cache_ttl_secs
            .unwrap_or(existing.supported_cache_ttl_secs),
        enabled: patch.enabled.unwrap_or(existing.enabled),
    };

    let default_headers = serde_json::to_value(merged.default_headers).map_err(|err| {
        LibError::invalid(
            "Failed to encode facilitator headers",
            anyhow!("update_facilitator_profile encode headers failed: {err}"),
        )
    })?;

    let row = sqlx::query_as::<_, FacilitatorProfileRow>(
        r#"
        UPDATE x402.facilitator_profiles
        SET
            name = $2,
            verify_url = $3,
            settle_url = $4,
            supported_url = $5,
            default_headers = $6,
            timeout_ms = $7,
            supported_cache_ttl_secs = $8,
            enabled = $9,
            updated_at = NOW()
        WHERE id = $1
        RETURNING
            id,
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled,
            created_at,
            updated_at
        "#,
    )
    .bind(id)
    .bind(merged.name)
    .bind(merged.verify_url)
    .bind(merged.settle_url)
    .bind(merged.supported_url)
    .bind(default_headers)
    .bind(merged.timeout_ms)
    .bind(merged.supported_cache_ttl_secs)
    .bind(merged.enabled)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            LibError::conflict(
                "Facilitator profile name already exists",
                anyhow!("update_facilitator_profile unique violation: {err}"),
            )
        } else {
            LibError::database(
                "Failed to update facilitator profile",
                anyhow!("update_facilitator_profile failed: {err}"),
            )
        }
    })?;

    row.map(row_to_model).transpose()
}

pub async fn delete_facilitator_profile(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM x402.facilitator_profiles
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to delete facilitator profile",
            anyhow!("delete_facilitator_profile failed: {err}"),
        )
    })?;

    Ok(result.rows_affected() > 0)
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    let sqlx::Error::Database(db_err) = err else {
        return false;
    };
    db_err.code().as_deref() == Some("23505")
}
