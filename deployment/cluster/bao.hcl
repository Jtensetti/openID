ui = false
api_addr = "https://bao.internal:8200"
cluster_addr = "https://bao.internal:8201"
# Raft uses mmap: mlock must be disabled and the host must prohibit swap.
disable_mlock = true
storage "raft" {
  path = "/var/lib/openbao"
  node_id = "bao-1"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/run/secrets/bao.pem"
  tls_key_file = "/run/secrets/bao.key"
  tls_min_version = "tls12"
}
