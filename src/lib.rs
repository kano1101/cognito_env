use async_trait::async_trait;
use token_cognito::{GetAuthInfo, TokenClient};

pub async fn get_token_cache_or_auth(
    region: &'static str,
    secrets_manager_id: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<&'static (String, String, String)> {
    static mut TOKENS: Option<(String, String, String)> = None;
    unsafe {
        if TOKENS.is_none() {
            TOKENS = auth(region, secrets_manager_id, username, password)
                .await
                .ok();
        }
    }
    unsafe {
        TOKENS
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("failed to get token cache or auth"))
    }
}

struct GetAuthInfoFromEnv<'a> {
    region: &'static str,
    secrets_manager_id: &'a str,
}

#[async_trait]
impl<'a> GetAuthInfo<'a> for GetAuthInfoFromEnv<'a> {
    async fn run(&'a self) -> anyhow::Result<(String, String, String)> {
        use itertools::Itertools as _;
        use secret_env::get_secret_env_values_from_keys;
        let (secret_key, client_id, user_pool_id) = get_secret_env_values_from_keys(
            self.region,
            self.secrets_manager_id,
            vec!["APPLICATION_SECRET", "COGNITO_CLIENT_ID", "USER_POOL_ID"],
        )
        .await?
        .into_iter()
        .collect_tuple()
        .ok_or(anyhow::anyhow!("failed to secret env collect tuple"))?;
        Ok((secret_key, client_id, user_pool_id))
    }
}

async fn auth<'a>(
    region: &'static str,
    secrets_manager_id: &'a str,
    username: &'a str,
    password: &'a str,
) -> anyhow::Result<(String, String, String)> {
    let getter = GetAuthInfoFromEnv {
        region,
        secrets_manager_id,
    };
    let token_client = TokenClient::builder().set_getter(Some(&getter)).build();

    let tokens = token_client.run(username, password).await?;

    Ok(tokens)
}
