use once_cell::sync::Lazy;
use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};

pub mod audit;
pub mod facilitator;
pub mod policy;

pub static MIGRATOR: Lazy<Migrator> = Lazy::new(|| {
    let mut migrator = sqlx::migrate!("./migrations");
    migrator.set_ignore_missing(true);
    migrator
});

pub async fn create_x402_tables(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

pub use audit::{create_payment_audit, list_payment_audit};
pub use facilitator::{
    create_facilitator_profile, delete_facilitator_profile, get_facilitator_profile,
    list_facilitator_profiles, update_facilitator_profile,
};
pub use policy::{
    create_route_policy, delete_route_policy, get_route_policy, list_route_policies,
    resolve_route_policy, update_route_policy,
};
