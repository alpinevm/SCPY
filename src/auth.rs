use opaque_ke::{
    argon2::Argon2, ciphersuite::CipherSuite, ClientLogin, ClientLoginFinishResult,
    ClientLoginStartResult, ClientRegistration, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, Ristretto255, ServerLogin,
    ServerRegistration, ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

pub struct ScpyOpaqueCipherSuite;

impl CipherSuite for ScpyOpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub type OpaqueClientRegistration = ClientRegistration<ScpyOpaqueCipherSuite>;
pub type OpaqueClientRegistrationStart = ClientRegistrationStartResult<ScpyOpaqueCipherSuite>;
pub type OpaqueClientRegistrationFinish = ClientRegistrationFinishResult<ScpyOpaqueCipherSuite>;
pub type OpaqueClientLogin = ClientLogin<ScpyOpaqueCipherSuite>;
pub type OpaqueClientLoginStart = ClientLoginStartResult<ScpyOpaqueCipherSuite>;
pub type OpaqueClientLoginFinish = ClientLoginFinishResult<ScpyOpaqueCipherSuite>;
pub type OpaqueRegistrationRequest = RegistrationRequest<ScpyOpaqueCipherSuite>;
pub type OpaqueRegistrationResponse = RegistrationResponse<ScpyOpaqueCipherSuite>;
pub type OpaqueRegistrationUpload = RegistrationUpload<ScpyOpaqueCipherSuite>;
pub type OpaqueCredentialRequest = CredentialRequest<ScpyOpaqueCipherSuite>;
pub type OpaqueCredentialResponse = CredentialResponse<ScpyOpaqueCipherSuite>;
pub type OpaqueCredentialFinalization = CredentialFinalization<ScpyOpaqueCipherSuite>;
pub type OpaqueServerRegistration = ServerRegistration<ScpyOpaqueCipherSuite>;
pub type OpaqueServerLogin = ServerLogin<ScpyOpaqueCipherSuite>;
pub type OpaqueServerSetup = ServerSetup<ScpyOpaqueCipherSuite>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueRegistrationStartRequest {
    pub message: OpaqueRegistrationRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueRegistrationStartResponse {
    pub credential_id: Vec<u8>,
    pub message: OpaqueRegistrationResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueRoomRegistration {
    pub credential_id: Vec<u8>,
    pub registration_upload: OpaqueRegistrationUpload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueLoginStartRequest {
    pub room_id: String,
    pub message: OpaqueCredentialRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueLoginStartResponse {
    pub login_session_id: String,
    pub message: OpaqueCredentialResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueLoginFinishRequest {
    pub login_session_id: String,
    pub message: OpaqueCredentialFinalization,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpaqueLoginFinishResponse {
    pub authenticated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredOpaqueRegistration {
    pub credential_id: Vec<u8>,
    pub password_file: OpaqueServerRegistration,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredOpaqueLoginState {
    pub room_id: String,
    pub state: OpaqueServerLogin,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredOpaqueSession {
    pub room_id: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

pub fn new_server_setup() -> OpaqueServerSetup {
    let mut rng = OsRng;
    OpaqueServerSetup::new(&mut rng)
}
