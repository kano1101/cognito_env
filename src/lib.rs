use async_trait::async_trait;
use token_cognito::{GetAuthInfo, TokenClient};

pub async fn get_token_cache_or_auth(
    username: &str,
    password: &str,
) -> anyhow::Result<&'static (String, String, String)> {
    static mut TOKENS: Option<(String, String, String)> = None;
    unsafe {
        if TOKENS.is_none() {
            TOKENS = auth(username, password).await.ok();
        }
    }
    unsafe {
        TOKENS
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("failed to get token cache or auth"))
    }
}

struct GetAuthInfoFromEnv;

#[async_trait]
impl GetAuthInfo for GetAuthInfoFromEnv {
    async fn run(&self) -> anyhow::Result<(String, String, String)> {
        use itertools::Itertools as _;
        use secret_env::get_secret_env_values_from_keys;
        let region = "ap-northeast-1";
        let secret_name = "SecretsManager";
        let (secret_key, client_id, user_pool_id) = get_secret_env_values_from_keys(
            region,
            secret_name,
            vec!["APPLICATION_SECRET", "COGNITO_CLIENT_ID", "USER_POOL_ID"],
        )
        .await?
        .into_iter()
        .collect_tuple()
        .ok_or(anyhow::anyhow!("failed to secret env collect tuple"))?;
        Ok((secret_key, client_id, user_pool_id))
    }
}

async fn auth(username: &str, password: &str) -> anyhow::Result<(String, String, String)> {
    let token_client = TokenClient::builder()
        .set_getter(Some(&GetAuthInfoFromEnv))
        .build();

    let tokens = token_client.run(username, password).await?;

    Ok(tokens)
}
