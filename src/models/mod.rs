pub mod audit;
pub mod auth;
pub mod facilitator;
pub mod policy;

pub use audit::{
    CreatePaymentAudit, PaymentAuditApi, PaymentAuditChannel, PaymentAuditDb,
    PaymentAuditListQuery, PaymentAuditResult,
};
pub use auth::{
    ApiKeyProof, AuthChannelResult, DEFAULT_ADMIN_ROLE, DEFAULT_READ_ROLE, X402_ROLE_SCOPE,
    X402_ROLE_SCOPE_ID, X402AuthContext, X402Proof,
};
pub use facilitator::{
    CreateFacilitatorProfileDb, CreateFacilitatorProfileRequest, FacilitatorProfileApi,
    FacilitatorProfileDb, UpdateFacilitatorProfileDb, UpdateFacilitatorProfileRequest,
};
pub use policy::{
    AuthChannel, AuthMode, CreateRoutePolicyDb, CreateRoutePolicyRequest, RoutePolicyApi,
    RoutePolicyDb, RoutePolicyListQuery, UpdateRoutePolicyDb, UpdateRoutePolicyRequest,
    X402RequirementApi, X402RequirementDb,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequireRole {
    Read,
    Write,
}
