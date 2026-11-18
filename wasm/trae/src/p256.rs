//! 一次性 P-256（secp256r1）密钥对：只为登录那一步服务。
//!
//! ── 为什么要在插件里自己算这一小段 ──────────────────────────
//! 官方 `ExchangeToken` 要求 `DeviceInfo.DevicePublicKey` 是一把**合法的**
//! P-256 公钥（SPKI PEM），空值或畸形值会被判 HTTP 401 / 业务码 20405
//! （设备绑定拒绝，2026-09-04 实测，见 native `device.rs` 的模块头）。
//! 而插件的依赖只有 sdk / serde_json / sha2 / chrono 四件，没有 p256 / ring
//! 可借，宿主也没有暴露"生成密钥对"的能力 —— 所以这里实现登录真正用到的
//! 那一小块：标量乘、仿射化、SEC1 与 PKCS#8 编码。
//!
//! **不**做签名 / 验签：整条凭据链上没有任何一步用私钥（native 的说明是
//! 「参考实现只写不读」，私钥落盘只为保住设备绑定关系）。
//!
//! ── 自检 ────────────────────────────────────────────────────
//! `cargo test -p agent2api-wasm-trae` 里有四条已知答案（Montgomery 往返、
//! 1·G == G、2·G == 公开测试向量、SPKI 前缀）。算术写错时编译照样通过，
//! 但登录会被上游拒 —— 所以要跑测试，别只看 `cargo check`。

type U256 = [u64; 4];

/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const P: U256 = [0xffffffffffffffff, 0x00000000ffffffff, 0, 0xffffffff00000001];
const P_MINUS_2: U256 = [0xfffffffffffffffd, 0x00000000ffffffff, 0, 0xffffffff00000001];
/// n（曲线阶）：标量必须落在 `[1, n-1]`。
const ORDER: U256 = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];
const ONE: U256 = [1, 0, 0, 0];
/// n0 = -p^{-1} mod 2^64；p ≡ -1 (mod 2^64)，所以这里是 1。
const N0: u64 = 1;

const GENERATOR_X: U256 = [
    0xf4a13945d898c296,
    0x77037d812deb33a0,
    0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247,
];
const GENERATOR_Y: U256 = [
    0xcbb6406837bf51f5,
    0x2bce33576b315ece,
    0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b,
];

fn is_zero(value: &U256) -> bool {
    value.iter().all(|limb| *limb == 0)
}

fn greater_or_equal(left: &U256, right: &U256) -> bool {
    for index in (0..4).rev() {
        if left[index] != right[index] {
            return left[index] > right[index];
        }
    }
    true
}

/// 逐 limb 相加（模 2^256，丢弃进位）。
fn add_wrapping(left: &U256, right: &U256) -> U256 {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let sum = left[index] as u128 + right[index] as u128 + carry;
        out[index] = sum as u64;
        carry = sum >> 64;
    }
    out
}

/// 逐 limb 相减（模 2^256），返回 (结果, 是否借位)。
fn sub_wrapping(left: &U256, right: &U256) -> (U256, bool) {
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for index in 0..4 {
        let minuend = left[index] as u128;
        let subtrahend = right[index] as u128 + borrow;
        if minuend >= subtrahend {
            out[index] = (minuend - subtrahend) as u64;
            borrow = 0;
        } else {
            out[index] = ((minuend + (1u128 << 64)) - subtrahend) as u64;
            borrow = 1;
        }
    }
    (out, borrow != 0)
}

/// (a + b) mod p，入参均 < p。
fn add(left: &U256, right: &U256) -> U256 {
    let mut sum = [0u64; 4];
    let mut carry = 0u128;
    for index in 0..4 {
        let value = left[index] as u128 + right[index] as u128 + carry;
        sum[index] = value as u64;
        carry = value >> 64;
    }
    // 溢出（carry）时真实值是 sum + 2^256，减 p 后的形态与 wrap 减一致。
    if carry != 0 || greater_or_equal(&sum, &P) {
        sub_wrapping(&sum, &P).0
    } else {
        sum
    }
}

/// (a - b) mod p，入参均 < p。
fn sub(left: &U256, right: &U256) -> U256 {
    let (difference, borrowed) = sub_wrapping(left, right);
    if borrowed {
        add_wrapping(&difference, &P)
    } else {
        difference
    }
}

/// Montgomery 乘法（CIOS，R = 2^256，n0 = 1）。
fn mont_mul(left: &U256, right: &U256) -> U256 {
    let mut t = [0u64; 6];
    for index in 0..4 {
        let mut carry: u128 = 0;
        for limb in 0..4 {
            let sum = (left[index] as u128) * (right[limb] as u128) + (t[limb] as u128) + carry;
            t[limb] = sum as u64;
            carry = sum >> 64;
        }
        let sum = (t[4] as u128) + carry;
        t[4] = sum as u64;
        t[5] = t[5].wrapping_add((sum >> 64) as u64);

        let factor = t[0].wrapping_mul(N0);
        let mut carry: u128 = 0;
        for limb in 0..4 {
            let sum = (factor as u128) * (P[limb] as u128) + (t[limb] as u128) + carry;
            t[limb] = sum as u64;
            carry = sum >> 64;
        }
        let sum = (t[4] as u128) + carry;
        t[4] = sum as u64;
        t[5] = t[5].wrapping_add((sum >> 64) as u64);

        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = t[5];
        t[5] = 0;
    }
    let mut out = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || greater_or_equal(&out, &P) {
        out = sub_wrapping(&out, &P).0;
    }
    out
}

fn mont_sqr(value: &U256) -> U256 {
    mont_mul(value, value)
}

/// R^2 mod p：从 1 起做 512 次翻倍（比手写常数更难写错，而且只跑一次）。
fn r_squared() -> U256 {
    let mut value = ONE;
    for _ in 0..512 {
        value = add(&value, &value);
    }
    value
}

fn to_mont(value: &U256) -> U256 {
    mont_mul(value, &r_squared())
}

fn from_mont(value: &U256) -> U256 {
    mont_mul(value, &ONE)
}

/// 模 p 求逆（费马小定理：a^(p-2)）。
fn invert(value: &U256) -> U256 {
    let mut result = to_mont(&ONE);
    let base = *value;
    for bit in (0..256).rev() {
        result = mont_sqr(&result);
        let word = P_MINUS_2[bit / 64];
        if (word >> (bit % 64)) & 1 == 1 {
            result = mont_mul(&result, &base);
        }
    }
    result
}

#[derive(Clone, Copy)]
struct Point {
    x: U256,
    y: U256,
    z: U256,
}

impl Point {
    fn infinity() -> Self {
        Self { x: ONE, y: ONE, z: [0, 0, 0, 0] }
    }

    fn is_infinity(&self) -> bool {
        is_zero(&self.z)
    }

    fn generator() -> Self {
        Self { x: to_mont(&GENERATOR_X), y: to_mont(&GENERATOR_Y), z: to_mont(&ONE) }
    }
}

/// Jacobian 翻倍（`dbl-2009-l`，a = -3）。
fn double(point: &Point) -> Point {
    if point.is_infinity() {
        return Point::infinity();
    }
    let a = mont_sqr(&point.x);
    let b = mont_sqr(&point.y);
    let c = mont_sqr(&b);
    let x_plus_b = add(&point.x, &b);
    let d = sub(&sub(&mont_sqr(&x_plus_b), &a), &c);
    let d = add(&d, &d);
    let z_squared = mont_sqr(&point.z);
    let e = {
        let three_a = add(&add(&a, &a), &a);
        let z_fourth = mont_sqr(&z_squared);
        let three_z = add(&add(&z_fourth, &z_fourth), &z_fourth);
        sub(&three_a, &three_z)
    };
    let f = mont_sqr(&e);
    let x3 = sub(&f, &add(&d, &d));
    let eight_c = {
        let twice = add(&c, &c);
        let four = add(&twice, &twice);
        add(&four, &four)
    };
    let y3 = sub(&mont_mul(&e, &sub(&d, &x3)), &eight_c);
    let yz = mont_mul(&point.y, &point.z);
    Point { x: x3, y: y3, z: add(&yz, &yz) }
}

/// Jacobian 相加（`add-2007-bl`，任意 a）。
fn add_point(left: &Point, right: &Point) -> Point {
    if left.is_infinity() {
        return *right;
    }
    if right.is_infinity() {
        return *left;
    }
    let z1z1 = mont_sqr(&left.z);
    let z2z2 = mont_sqr(&right.z);
    let u1 = mont_mul(&left.x, &z2z2);
    let u2 = mont_mul(&right.x, &z1z1);
    let s1 = mont_mul(&mont_mul(&left.y, &right.z), &z2z2);
    let s2 = mont_mul(&mont_mul(&right.y, &left.z), &z1z1);
    let h = sub(&u2, &u1);
    let r = {
        let difference = sub(&s2, &s1);
        add(&difference, &difference)
    };
    if is_zero(&h) {
        if is_zero(&r) {
            return double(left);
        }
        return Point::infinity();
    }
    let two_h = add(&h, &h);
    let i = mont_sqr(&two_h);
    let j = mont_mul(&h, &i);
    let v = mont_mul(&u1, &i);
    let x3 = sub(&sub(&mont_sqr(&r), &j), &add(&v, &v));
    let y3 = sub(&mont_mul(&r, &sub(&v, &x3)), &{
        let twice = add(&s1, &s1);
        mont_mul(&twice, &j)
    });
    let z3 = mont_mul(
        &sub(&sub(&mont_sqr(&add(&left.z, &right.z)), &z1z1), &z2z2),
        &h,
    );
    Point { x: x3, y: y3, z: z3 }
}

fn scalar_mul(scalar: &U256, base: &Point) -> Point {
    let mut result = Point::infinity();
    for bit in (0..256).rev() {
        result = double(&result);
        let word = scalar[bit / 64];
        if (word >> (bit % 64)) & 1 == 1 {
            result = add_point(&result, base);
        }
    }
    result
}

/// 仿射坐标（已经转出 Montgomery 域；大端 32 字节由调用方拼）。
fn to_affine(point: &Point) -> Option<(U256, U256)> {
    if point.is_infinity() {
        return None;
    }
    let z_inverse = invert(&point.z);
    let z_inverse_squared = mont_sqr(&z_inverse);
    let x = from_mont(&mont_mul(&point.x, &z_inverse_squared));
    let y = from_mont(&mont_mul(&point.y, &mont_mul(&z_inverse_squared, &z_inverse)));
    Some((x, y))
}

fn to_bytes(value: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for index in 0..4 {
        let limb = value[3 - index].to_be_bytes();
        out[index * 8..index * 8 + 8].copy_from_slice(&limb);
    }
    out
}

/// 私钥标量 → 65 字节 SEC1 未压缩公钥（`0x04 || X || Y`）。
/// 标量不在 `[1, n-1]` 时返回 `None`，调用方重取（native 同一条：不假定一次成功）。
pub fn public_key_sec1(scalar: &[u8; 32]) -> Option<[u8; 65]> {
    let value = from_be_bytes(scalar);
    if is_zero(&value) || greater_or_equal(&value, &ORDER) {
        return None;
    }
    let point = scalar_mul(&value, &Point::generator());
    let (x, y) = to_affine(&point)?;
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&to_bytes(&x));
    out[33..65].copy_from_slice(&to_bytes(&y));
    Some(out)
}

fn from_be_bytes(bytes: &[u8; 32]) -> U256 {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        out[3 - index] = u64::from_be_bytes(limb);
    }
    out
}

/// SPKI（`id-ecPublicKey` + `prime256v1`）DER。长度是写死的 91 字节，
/// 与 Go `x509.MarshalPKIXPublicKey` 逐字节同形。
pub fn spki_der(sec1: &[u8; 65]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x59, // SEQUENCE (89)
        0x30, 0x13, // AlgorithmIdentifier (19)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        0x03, 0x42, 0x00, // BIT STRING (66)，首字节 0 = unused bits
    ];
    out.extend_from_slice(sec1);
    out
}

/// PKCS#8（`ECPrivateKey` 内嵌 + 公钥）DER，150 字节。
///
/// 私钥只写不用（见模块头），但形状必须对：将来若有人拿它去对拍或
/// 恢复设备绑定，一份畸形 DER 会让排查方向全错。
pub fn pkcs8_der(scalar: &[u8; 32], sec1: &[u8; 65]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x81, 0x93, // SEQUENCE (147)
        0x02, 0x01, 0x00, // version 0
        0x30, 0x13, // AlgorithmIdentifier (19)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x04, 0x79, // OCTET STRING (121)
        0x30, 0x77, // ECPrivateKey SEQUENCE (119)
        0x02, 0x01, 0x01, // version 1
        0x04, 0x20, // privateKey OCTET STRING (32)
    ];
    out.extend_from_slice(scalar);
    out.extend_from_slice(&[
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // [0] parameters
        0xa1, 0x44, 0x03, 0x42, 0x00, // [1] publicKey BIT STRING (66)
    ]);
    out.extend_from_slice(sec1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    #[test]
    fn montgomery_round_trip() {
        let two = to_mont(&[2, 0, 0, 0]);
        let three = to_mont(&[3, 0, 0, 0]);
        assert_eq!(from_mont(&mont_mul(&two, &three)), [6, 0, 0, 0]);
        assert_eq!(from_mont(&mont_mul(&to_mont(&ONE), &to_mont(&ONE))), ONE);
        let big = [0x0123456789abcdef, 0xfedcba9876543210, 0x0f0f0f0f0f0f0f0f, 0x0011223344556677];
        let inverse = invert(&to_mont(&big));
        assert_eq!(from_mont(&mont_mul(&to_mont(&big), &inverse)), ONE);
    }

    #[test]
    fn generator_is_one_times_g() {
        let point = public_key_sec1(&scalar(1)).unwrap_or([0u8; 65]);
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], &to_bytes(&GENERATOR_X));
        assert_eq!(&point[33..65], &to_bytes(&GENERATOR_Y));
    }

    #[test]
    fn two_times_g_matches_test_vector() {
        // NIST P-256 公开测试向量：2·G
        let expected_x = [
            0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
            0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
        ];
        let expected_y = [
            0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
            0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
        ];
        let point = public_key_sec1(&scalar(2)).unwrap_or([0u8; 65]);
        assert_eq!(&point[1..33], &expected_x);
        assert_eq!(&point[33..65], &expected_y);
    }

    #[test]
    fn spki_prefix_is_stable() {
        let point = public_key_sec1(&scalar(1)).unwrap_or([0u8; 65]);
        let der = spki_der(&point);
        assert_eq!(der.len(), 91);
        assert_eq!(&der[..26], &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]);
        let pkcs8 = pkcs8_der(&scalar(1), &point);
        assert_eq!(pkcs8.len(), 150);
        assert_eq!(&pkcs8[..10], &[0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07]);
    }
}
