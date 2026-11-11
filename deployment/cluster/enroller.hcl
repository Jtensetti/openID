path "transit/encrypt/openid-profile" { capabilities = ["update"] }
path "transit/hmac/openid-index/sha2-256" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
