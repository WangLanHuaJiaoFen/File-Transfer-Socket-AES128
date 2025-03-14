use crate::dh_p_g::DHParams;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub struct DHKeyPair {
    private_key: BigUint,
    public_key: BigUint,
    p_g: DHParams,
}

impl DHKeyPair {
    pub fn new() -> Self {
        let mut rng = OsRng;
        // 生成参数
        let params = DHParams::default();
        // 生成私钥
        let private_key = rng.gen_biguint_range(&BigUint::from(1u32), &params.p);
        // 计算公钥
        let public_key = params.g.modpow(&private_key, &params.p);
        DHKeyPair {
            private_key,
            public_key,
            p_g: params,
        }
    }

    fn calculate_shared_secret_key(&self, other_pub: &BigUint) -> BigUint {
        other_pub.modpow(&self.private_key, &self.p_g.p)
    }

    pub fn calculate_shared_secret_key_with_bytes(&self, other_pub: &[u8; 256]) -> [u8; 16] {
        let other_pub = BigUint::from_bytes_be(other_pub);
        self.derive_aes_key(&other_pub)
    }

    pub fn public_key(&self) -> &BigUint {
        &self.public_key
    }

    pub fn derive_aes_key(&self, other_pub: &BigUint) -> [u8; 16] {
        // 计算aes128位密钥
        let shared_secret_key = self.calculate_shared_secret_key(other_pub);
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret_key.to_bytes_be());
        let hash = hasher.finalize();
        // 散列然后取前128位作为aes密钥
        hash[..16].try_into().unwrap()
    }
}
