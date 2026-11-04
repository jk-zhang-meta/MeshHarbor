// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use meshharbor_config::OAuthSettings;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Provider not configured: {0}")]
    ProviderNotConfigured(String),
    #[error("Unknown provider: {0}")]
    UnknownProvider(String),
    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),
    #[error("User info fetch failed: {0}")]
    UserInfoFailed(String),
    #[error("Invalid state parameter")]
    InvalidState,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider: String,
    pub provider_id: String,
    pub email: String,
    pub name: String,
    pub avatar_url: Option<String>,
    /// Did the PROVIDER prove this address belongs to this identity?
    ///
    /// Only a true here may link the sign-in to an existing account by
    /// email ([`crate::dao::user::UserDao::find_or_create_by_oauth`]).
    /// `false` is not a rejection — the identity still signs in, it just
    /// gets its own account instead of inheriting one that happens to
    /// share an address.
    ///
    /// Microsoft is the reason this exists: the multi-tenant `common`
    /// endpoint hands back a `mail` attribute that ANY Entra tenant admin
    /// can set to an arbitrary string, including someone else's Gmail
    /// address (the "nOAuth" class of account takeover). Its `id` is
    /// still a real assertion, so provider-id matching stays trusted.
    pub email_verified: bool,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GoogleUser {
    id: String,
    email: Option<String>,
    /// Google explicitly documents that consumers MUST check this before
    /// trusting `email` — an unverified address must never drive the
    /// find-by-email account-linking step (account-takeover vector).
    verified_email: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FacebookUser {
    id: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<FacebookPicture>,
}

#[derive(Debug, Deserialize)]
struct FacebookPicture {
    data: Option<FacebookPictureData>,
}

#[derive(Debug, Deserialize)]
struct FacebookPictureData {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct LinkedInUser {
    sub: Option<String>,
    email: Option<String>,
    /// OIDC standard claim — LinkedIn sends it; absent ⇒ untrusted.
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftUser {
    id: String,
    display_name: Option<String>,
    given_name: Option<String>,
    mail: Option<String>,
    user_principal_name: Option<String>,
}

pub struct OAuthService {
    settings: OAuthSettings,
    client: reqwest::Client,
}

impl OAuthService {
    pub fn new(settings: OAuthSettings) -> Self {
        Self {
            settings,
            client: reqwest::Client::new(),
        }
    }

    fn provider_config(&self, provider: &str) -> Result<(&str, &str), OAuthError> {
        let cfg = match provider {
            "google" => (
                &self.settings.google.client_id,
                &self.settings.google.client_secret,
            ),
            "facebook" => (
                &self.settings.facebook.client_id,
                &self.settings.facebook.client_secret,
            ),
            "github" => (
                &self.settings.github.client_id,
                &self.settings.github.client_secret,
            ),
            "linkedin" => (
                &self.settings.linkedin.client_id,
                &self.settings.linkedin.client_secret,
            ),
            "microsoft" => (
                &self.settings.microsoft.client_id,
                &self.settings.microsoft.client_secret,
            ),
            _ => return Err(OAuthError::UnknownProvider(provider.to_string())),
        };
        if cfg.0.is_empty() {
            return Err(OAuthError::ProviderNotConfigured(provider.to_string()));
        }
        Ok((cfg.0.as_str(), cfg.1.as_str()))
    }

    fn callback_url(&self, provider: &str) -> String {
        format!("{}/api/oauth/callback/{}", self.settings.base_url, provider)
    }

    pub fn build_auth_url(&self, provider: &str, state: &str) -> Result<String, OAuthError> {
        let (client_id, _) = self.provider_config(provider)?;
        let redirect_uri = self.callback_url(provider);

        let url = match provider {
            "google" => format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email+profile&state={}&access_type=offline",
                client_id,
                urlencoding::encode(&redirect_uri),
                urlencoding::encode(state)
            ),
            "facebook" => format!(
                "https://www.facebook.com/v18.0/dialog/oauth?client_id={}&redirect_uri={}&response_type=code&scope=email&state={}",
                client_id,
                urlencoding::encode(&redirect_uri),
                urlencoding::encode(state)
            ),
            "github" => format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user+user:email&state={}",
                client_id,
                urlencoding::encode(&redirect_uri),
                urlencoding::encode(state)
            ),
            "linkedin" => format!(
                "https://www.linkedin.com/oauth/v2/authorization?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile+email&state={}",
                client_id,
                urlencoding::encode(&redirect_uri),
                urlencoding::encode(state)
            ),
            "microsoft" => format!(
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile+email+User.Read&state={}",
                client_id,
                urlencoding::encode(&redirect_uri),
                urlencoding::encode(state)
            ),
            _ => return Err(OAuthError::UnknownProvider(provider.to_string())),
        };

        Ok(url)
    }

    async fn exchange_code(&self, provider: &str, code: &str) -> Result<String, OAuthError> {
        let (client_id, client_secret) = self.provider_config(provider)?;
        let redirect_uri = self.callback_url(provider);

        let access_token = match provider {
            "google" => {
                let resp = self
                    .client
                    .post("https://oauth2.googleapis.com/token")
                    .form(&[
                        ("code", code),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("redirect_uri", &redirect_uri),
                        ("grant_type", "authorization_code"),
                    ])
                    .send()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                let body: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                body.access_token
            }
            "facebook" => {
                let resp = self
                    .client
                    .get("https://graph.facebook.com/v18.0/oauth/access_token")
                    .query(&[
                        ("code", code),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("redirect_uri", &redirect_uri),
                    ])
                    .send()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                let body: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                body.access_token
            }
            "github" => {
                let resp = self
                    .client
                    .post("https://github.com/login/oauth/access_token")
                    .header("Accept", "application/json")
                    .form(&[
                        ("code", code),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("redirect_uri", &redirect_uri),
                    ])
                    .send()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                let body: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                body.access_token
            }
            "linkedin" => {
                let resp = self
                    .client
                    .post("https://www.linkedin.com/oauth/v2/accessToken")
                    .form(&[
                        ("code", code),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("redirect_uri", &redirect_uri),
                        ("grant_type", "authorization_code"),
                    ])
                    .send()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                let body: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                body.access_token
            }
            "microsoft" => {
                let resp = self
                    .client
                    .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
                    .form(&[
                        ("code", code),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("redirect_uri", &redirect_uri),
                        ("grant_type", "authorization_code"),
                    ])
                    .send()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                let body: TokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| OAuthError::TokenExchangeFailed(e.to_string()))?;
                body.access_token
            }
            _ => return Err(OAuthError::UnknownProvider(provider.to_string())),
        };

        Ok(access_token)
    }

    async fn fetch_user_info(
        &self,
        provider: &str,
        access_token: &str,
    ) -> Result<OAuthUserInfo, OAuthError> {
        match provider {
            "google" => {
                let user: GoogleUser = self
                    .client
                    .get("https://www.googleapis.com/userinfo/v2/me")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
                let name = user.name.unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        user.given_name.unwrap_or_default(),
                        user.family_name.unwrap_or_default()
                    )
                    .trim()
                    .to_string()
                });
                // Google states the claim explicitly; absent ⇒ treat as
                // unverified rather than assuming in our own favour.
                let email_verified = user.verified_email == Some(true);
                if !email_verified {
                    tracing::warn!(
                        provider_id = %user.id,
                        "google oauth: unverified email — no email-based account linking"
                    );
                }
                Ok(OAuthUserInfo {
                    provider: "google".to_string(),
                    provider_id: user.id,
                    email: user.email.unwrap_or_default(),
                    name,
                    avatar_url: user.picture,
                    email_verified,
                })
            }
            "facebook" => {
                let user: FacebookUser = self
                    .client
                    .get(
                        "https://graph.facebook.com/v18.0/me?fields=email,name,picture.type(large)",
                    )
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
                let avatar = user.picture.and_then(|p| p.data).and_then(|d| d.url);
                // Facebook only returns `email` once the address is
                // confirmed on the account, so its presence IS the proof.
                let email = user.email.unwrap_or_default();
                let email_verified = !email.is_empty();
                Ok(OAuthUserInfo {
                    provider: "facebook".to_string(),
                    provider_id: user.id,
                    email,
                    name: user.name.unwrap_or_default(),
                    avatar_url: avatar,
                    email_verified,
                })
            }
            "github" => {
                let user: GitHubUser = self
                    .client
                    .get("https://api.github.com/user")
                    .header("User-Agent", "roomler-ai")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;

                // The profile's public `email` is user-chosen and carries
                // no verification claim, so it is NOT a linking basis.
                // `/user/emails` is: take the primary+verified one, which
                // is also what an account-recovery flow would use.
                let emails: Vec<GitHubEmail> = self
                    .client
                    .get("https://api.github.com/user/emails")
                    .header("User-Agent", "roomler-ai")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .unwrap_or_default();
                let verified = emails
                    .into_iter()
                    .find(|e| e.primary && e.verified)
                    .map(|e| e.email);
                let email_verified = verified.is_some();
                let email = verified.or(user.email).unwrap_or_default();
                if !email_verified {
                    tracing::warn!(
                        provider_id = %user.id,
                        "github oauth: no primary+verified email — no email-based account linking"
                    );
                }

                Ok(OAuthUserInfo {
                    provider: "github".to_string(),
                    provider_id: user.id.to_string(),
                    email,
                    name: user.login,
                    email_verified,
                    avatar_url: user.avatar_url,
                })
            }
            "linkedin" => {
                let user: LinkedInUser = self
                    .client
                    .get("https://api.linkedin.com/v2/userinfo")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
                let name = user.name.unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        user.given_name.unwrap_or_default(),
                        user.family_name.unwrap_or_default()
                    )
                    .trim()
                    .to_string()
                });
                let email_verified = user.email_verified == Some(true);
                Ok(OAuthUserInfo {
                    provider: "linkedin".to_string(),
                    provider_id: user.sub.unwrap_or_default(),
                    email: user.email.unwrap_or_default(),
                    name,
                    avatar_url: user.picture,
                    email_verified,
                })
            }
            "microsoft" => {
                let user: MicrosoftUser = self
                    .client
                    .get("https://graph.microsoft.com/v1.0/me")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| OAuthError::UserInfoFailed(e.to_string()))?;
                let name = user.display_name.or(user.given_name).unwrap_or_default();
                let email = user.mail.or(user.user_principal_name).unwrap_or_default();
                // nOAuth: `mail` (and a UPN in a tenant the signer
                // controls) is self-asserted, so it must never link into
                // an existing account. The `id` (object id) is what
                // Microsoft actually proves — provider-id matching keeps
                // working, and returning users are unaffected.
                Ok(OAuthUserInfo {
                    provider: "microsoft".to_string(),
                    provider_id: user.id,
                    email,
                    name,
                    avatar_url: None,
                    email_verified: false,
                })
            }
            _ => Err(OAuthError::UnknownProvider(provider.to_string())),
        }
    }

    pub async fn authenticate(
        &self,
        provider: &str,
        code: &str,
    ) -> Result<OAuthUserInfo, OAuthError> {
        let access_token = self.exchange_code(provider, code).await?;
        self.fetch_user_info(provider, &access_token).await
    }
}
