//! P-256（secp256r1）算术与 **ECDSA/ES256 签名**：只为 DPoP 证明服务。
//!
//! ── 为什么要在插件里自己算这一整段 ──────────────────────────
//! 本家的登录与续期都要给 STS 令牌端点递一个 `DPoP:` 头，那是一份 **ES256 的 JWS**
//! （头部嵌公钥 JWK，载荷声明 `htm`/`htu`/`iat`/`jti`）。而插件的依赖只有
//! sdk / serde_json / sha2 / chrono 四件，没有 `p256` / `ring`，宿主也没有暴露
//! 「用私钥签一段 digest」的能力 —— 所以这里实现这条链真正用到的那一块：
//! 标量乘、仿射化、两个模数（曲线域 `p` 与群阶 `n`）的算术、以及 ECDSA 签名。
//!
//! ── 与 `wasm/trae/src/p256.rs` 的关系 ──────────────────────
//! 那边只做**公钥**（登录只写不读私钥，没有签名需求），所以只有 `p` 一个模数。
//! 这里多一个模数 `n`：ECDSA 的 `r`、`s`、`k^{-1}` 全在 `n` 上算，拿 `p` 去算
//! 会得到一个**自洽但错误**的签名 —— 上游回 401，且没有任何提示指向算术。
//! 所以算术函数全部参数化成 [`Modulus`]，两套模数共用一份实现。
//!
//! ── 随机数与 k（这一节是安全前提，别拿别处的随机源替换）────
//! [`sign`] 的 `k` 只从宿主的 `random.bytes`（`random.v1`）取，**取不到就拒绝签名**
//! 而不是退到时钟派生：ECDSA 的 `s = k^{-1}(z + r·d)` 一旦 `k` 可预测，两次签名
//! 就能解出私钥 `d`。`Chat-Id` / `jti` 那种一次性标识可以退化，这里不行。
//! 测试用的 [`sign_with_k`] 是唯一带固定 `k` 的入口，它只在 `#[cfg(test)]` 下可见。
//!
//! ── 自检 ────────────────────────────────────────────────────
//! `cargo test -p agent2api-wasm-officeace` 里有五条已知答案：Montgomery 往返、
//! 1·G == G、2·G 的 NIST 公开向量、模 `n` 的求逆、以及 **RFC 6979 附录 A.2.5 的
//! P-256/SHA-256 签名向量**（那条是独立来源，能证明整条 ECDSA 而不只是"自洽"）。
//! 算术写错时编译照样通过、check 也照样通过，但登录会以 401 / 400 失败 —— 所以要
//! 跑测试，别只看 `cargo check`。

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// 256 位整数的四个 64 位 limb，**低字节在前**（与 Montgomery 乘法的进位方向一致）。
type U256 = [u64; 4];

/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1（曲线域）
const P: U256 = [0xffffffffffffffff, 0x00000000ffffffff, 0, 0xffffffff00000001];
/// n（群阶）：标量必须落在 `[1, n-1]`。
const ORDER: U256 = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];
const ONE: U256 = [1, 0, 0, 0];

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

/// 一个模数及其 Montgomery 常数。
///
/// `n0 = -m^{-1} mod 2^64` 由 [`invert_mod_2_64`] 现算（不手抄常数：抄错一位
/// 会让所有乘法静默算错，而且错得很像"某个字段格式不对"）。
#[derive(Clone)]
pub struct Modulus {
    limbs: U256,
    /// `m - 2`：费马小定理求逆的指数
    minus2: U256,
    /// `-m^{-1} mod 2^64`
    n0: u64,
    /// `R^2 mod m`（R = 2^256）：进出 Montgomery 域用
    r2: U256,
}

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

/// odd 的 64 位模逆（Newton 迭代，每轮翻倍精度；`a² ≡ 1 (mod 8)` 对任意奇数成立）。
fn invert_mod_2_64(odd: u64) -> u64 {
    let mut x = odd;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(odd.wrapping_mul(x)));
    }
    x
}

impl Modulus {
    fn new(limbs: U256) -> Self {
        let (minus2, _) = sub_wrapping(&limbs, &[2, 0, 0, 0]);
        let n0 = 0u64.wrapping_sub(invert_mod_2_64(limbs[0]));
        let mut modulus = Self { limbs, minus2, n0, r2: ONE };
        // R^2 mod m：从 1 起做 512 次模 m 翻倍（比手写常数更难写错，而且只跑一次）
        let mut value = ONE;
        for _ in 0..512 {
            value = modulus.add(&value, &value);
        }
        modulus.r2 = value;
        modulus
    }

    /// (a + b) mod m，入参均 < m。
    fn add(&self, left: &U256, right: &U256) -> U256 {
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for index in 0..4 {
            let value = left[index] as u128 + right[index] as u128 + carry;
            sum[index] = value as u64;
            carry = value >> 64;
        }
        // 溢出（carry）时真实值是 sum + 2^256，减 m 后的形态与 wrap 减一致。
        if carry != 0 || greater_or_equal(&sum, &self.limbs) {
            sub_wrapping(&sum, &self.limbs).0
        } else {
            sum
        }
    }

    /// (a - b) mod m，入参均 < m。
    fn sub(&self, left: &U256, right: &U256) -> U256 {
        let (difference, borrowed) = sub_wrapping(left, right);
        if borrowed {
            add_wrapping(&difference, &self.limbs)
        } else {
            difference
        }
    }

    /// Montgomery 乘法（CIOS，R = 2^256）。
    fn mont_mul(&self, left: &U256, right: &U256) -> U256 {
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

            let factor = t[0].wrapping_mul(self.n0);
            let mut carry: u128 = 0;
            for limb in 0..4 {
                let sum = (factor as u128) * (self.limbs[limb] as u128) + (t[limb] as u128) + carry;
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
        if t[4] != 0 || greater_or_equal(&out, &self.limbs) {
            out = sub_wrapping(&out, &self.limbs).0;
        }
        out
    }

    fn to_mont(&self, value: &U256) -> U256 {
        self.mont_mul(value, &self.r2)
    }

    fn from_mont(&self, value: &U256) -> U256 {
        self.mont_mul(value, &ONE)
    }

    /// a·b mod m（对外形态：普通整数进出）。
    fn mul(&self, left: &U256, right: &U256) -> U256 {
        self.from_mont(&self.mont_mul(&self.to_mont(left), &self.to_mont(right)))
    }

    /// 模 m 求逆（费马小定理：a^(m-2)，m 为素数）——**入出都在 Montgomery 域**。
    ///
    /// 这个形态是刻意的：点运算里 `z` 本来就是 Montgomery 表示，多转一次就变成
    /// `z·R` 的逆，算出来的仿射坐标会自洽但全错（而错的方式很像"上游地址不对"）。
    fn invert_mont(&self, value_in_mont: &U256) -> U256 {
        let mut result = self.to_mont(&ONE);
        let base = *value_in_mont;
        for bit in (0..256).rev() {
            result = self.mont_mul(&result, &result);
            let word = self.minus2[bit / 64];
            if (word >> (bit % 64)) & 1 == 1 {
                result = self.mont_mul(&result, &base);
            }
        }
        result
    }

    /// 模 m 求逆（普通域：普通整数进出）。
    fn invert(&self, value: &U256) -> U256 {
        self.from_mont(&self.invert_mont(&self.to_mont(value)))
    }
}

/// 曲线域模数（点运算用）。
fn field() -> &'static Modulus {
    static MODULUS: OnceLock<Modulus> = OnceLock::new();
    MODULUS.get_or_init(|| Modulus::new(P))
}

/// 群阶模数（ECDSA 的 r / s / k^{-1} 用）。
fn order() -> &'static Modulus {
    static MODULUS: OnceLock<Modulus> = OnceLock::new();
    MODULUS.get_or_init(|| Modulus::new(ORDER))
}

// ── 点运算（Jacobian，恒在曲线域上）─────────────────────────

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
        let m = field();
        Self { x: m.to_mont(&GENERATOR_X), y: m.to_mont(&GENERATOR_Y), z: m.to_mont(&ONE) }
    }
}

/// Jacobian 翻倍（`dbl-2009-l`，a = -3）。
fn double(point: &Point) -> Point {
    if point.is_infinity() {
        return Point::infinity();
    }
    let m = field();
    let a = m.mont_mul(&point.x, &point.x);
    let b = m.mont_mul(&point.y, &point.y);
    let c = m.mont_mul(&b, &b);
    let x_plus_b = m.add(&point.x, &b);
    let d = m.sub(&m.sub(&m.mont_mul(&x_plus_b, &x_plus_b), &a), &c);
    let d = m.add(&d, &d);
    let z_squared = m.mont_mul(&point.z, &point.z);
    let e = {
        let three_a = m.add(&m.add(&a, &a), &a);
        let z_fourth = m.mont_mul(&z_squared, &z_squared);
        let three_z = m.add(&m.add(&z_fourth, &z_fourth), &z_fourth);
        m.sub(&three_a, &three_z)
    };
    let f = m.mont_mul(&e, &e);
    let x3 = m.sub(&f, &m.add(&d, &d));
    let eight_c = {
        let twice = m.add(&c, &c);
        let four = m.add(&twice, &twice);
        m.add(&four, &four)
    };
    let y3 = m.sub(&m.mont_mul(&e, &m.sub(&d, &x3)), &eight_c);
    let yz = m.mont_mul(&point.y, &point.z);
    Point { x: x3, y: y3, z: m.add(&yz, &yz) }
}

/// Jacobian 相加（`add-2007-bl`，任意 a）。
fn add_point(left: &Point, right: &Point) -> Point {
    if left.is_infinity() {
        return *right;
    }
    if right.is_infinity() {
        return *left;
    }
    let m = field();
    let z1z1 = m.mont_mul(&left.z, &left.z);
    let z2z2 = m.mont_mul(&right.z, &right.z);
    let u1 = m.mont_mul(&left.x, &z2z2);
    let u2 = m.mont_mul(&right.x, &z1z1);
    let s1 = m.mont_mul(&m.mont_mul(&left.y, &right.z), &z2z2);
    let s2 = m.mont_mul(&m.mont_mul(&right.y, &left.z), &z1z1);
    let h = m.sub(&u2, &u1);
    let r = {
        let difference = m.sub(&s2, &s1);
        m.add(&difference, &difference)
    };
    if is_zero(&h) {
        if is_zero(&r) {
            return double(left);
        }
        return Point::infinity();
    }
    let two_h = m.add(&h, &h);
    let i = m.mont_mul(&two_h, &two_h);
    let j = m.mont_mul(&h, &i);
    let v = m.mont_mul(&u1, &i);
    let x3 = m.sub(&m.sub(&m.mont_mul(&r, &r), &j), &m.add(&v, &v));
    let y3 = m.sub(&m.mont_mul(&r, &m.sub(&v, &x3)), &{
        let twice = m.add(&s1, &s1);
        m.mont_mul(&twice, &j)
    });
    let z3 = m.mont_mul(
        &m.sub(&m.sub(&m.mont_mul(&m.add(&left.z, &right.z), &m.add(&left.z, &right.z)), &z1z1), &z2z2),
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

/// 仿射坐标（已转出 Montgomery 域；交给调用方拼大端字节）。
fn to_affine(point: &Point) -> Option<(U256, U256)> {
    if point.is_infinity() {
        return None;
    }
    let m = field();
    let z_inverse = m.invert_mont(&point.z);
    let z_inverse_squared = m.mont_mul(&z_inverse, &z_inverse);
    let x = m.from_mont(&m.mont_mul(&point.x, &z_inverse_squared));
    let y = m.from_mont(&m.mont_mul(&point.y, &m.mont_mul(&z_inverse_squared, &z_inverse)));
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

fn from_be_bytes(bytes: &[u8; 32]) -> U256 {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        out[3 - index] = u64::from_be_bytes(limb);
    }
    out
}

/// 标量是否落在 `[1, n-1]`（私钥 / k 的合法域）——不合法的标量点乘出来是无穷远点。
pub fn valid_scalar(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(bytes);
    let value = from_be_bytes(&raw);
    !is_zero(&value) && !greater_or_equal(&value, &ORDER)
}

/// 私钥标量 → 65 字节 SEC1 未压缩公钥（`0x04 || X || Y`）。
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

/// 32 字节 digest 规约进 `[0, n-1]`：`n < 2^256 < 2n`，所以减一次就够。
fn reduce_once(value: U256) -> U256 {
    if greater_or_equal(&value, &ORDER) {
        sub_wrapping(&value, &ORDER).0
    } else {
        value
    }
}

/// 用**指定**的 `k` 做一次 ECDSA 签名（只有测试能调 —— 见模块头）。
///
/// 返回 `r || s`（各 32 字节大端，JOSE / ES256 的裸格式，不是 DER）。
fn sign_with_k(digest: &[u8; 32], scalar: &[u8; 32], k_bytes: &[u8; 32]) -> Option<[u8; 64]> {
    let d = from_be_bytes(scalar);
    if is_zero(&d) || greater_or_equal(&d, &ORDER) {
        return None;
    }
    let k = from_be_bytes(k_bytes);
    if is_zero(&k) || greater_or_equal(&k, &ORDER) {
        return None;
    }
    // R = k·G，r = R.x mod n
    let point = scalar_mul(&k, &Point::generator());
    let (x, _) = to_affine(&point)?;
    let r = reduce_once(x);
    if is_zero(&r) {
        return None;
    }
    // s = k^{-1} · (z + r·d) mod n
    let n = order();
    let z = reduce_once(from_be_bytes(digest));
    let rd = n.mul(&r, &d);
    let sum = n.add(&z, &rd);
    let k_inverse = n.invert(&k);
    let s = n.mul(&k_inverse, &sum);
    if is_zero(&s) {
        return None;
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&to_bytes(&r));
    out[32..].copy_from_slice(&to_bytes(&s));
    Some(out)
}

/// 用随机 `k` 签一段 digest，返回 `r || s`（各 32 字节大端）。
///
/// `k` 取不到宿主随机源时返回 `None`（**不退到时钟派生**，理由见模块头）。
pub fn sign(digest: &[u8; 32], scalar: &[u8; 32]) -> Option<[u8; 64]> {
    for _ in 0..8 {
        let raw = crate::util::secure_random_bytes(32)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        // 落在 [1, n-1] 之外就重取：`n` 与 2^256 只差一点点，重取次数期望接近 1。
        if let Some(signature) = sign_with_k(digest, scalar, &k) {
            return Some(signature);
        }
    }
    None
}

/// 对一段字节做 SHA-256（DPoP 的签名输入是 ASCII 的 `header.payload`）。
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SPKI（`id-ecPublicKey` + `prime256v1`）DER，91 字节。
///
/// 本家的 DPoP 头用 JWK 而不是 PEM，这份编码现在没有消费方；留着是因为它是
/// 把「这把私钥」讲清楚的最后一块（排查时拿它去对 openssl 的输出最省事）。
#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn from_hex(text: &str) -> Vec<u8> {
        crate::util::hex_decode(text).unwrap_or_default()
    }

    fn from_hex32(text: &str) -> Option<[u8; 32]> {
        let bytes = from_hex(text);
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }

    #[test]
    fn montgomery_round_trip() {
        let m = field();
        let two = m.to_mont(&[2, 0, 0, 0]);
        let three = m.to_mont(&[3, 0, 0, 0]);
        assert_eq!(m.from_mont(&m.mont_mul(&two, &three)), [6, 0, 0, 0]);
        assert_eq!(m.from_mont(&m.mont_mul(&m.to_mont(&ONE), &m.to_mont(&ONE))), ONE);
        let big = [0x0123456789abcdef, 0xfedcba9876543210, 0x0f0f0f0f0f0f0f0f, 0x0011223344556677];
        // 普通域的逆：倒回去乘应当还原 1
        assert_eq!(m.mul(&big, &m.invert(&big)), ONE);
        // Montgomery 域的逆：同样还原（`to_affine` 走的那条）
        assert_eq!(m.from_mont(&m.mont_mul(&m.to_mont(&big), &m.invert_mont(&m.to_mont(&big)))), ONE);
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
    fn order_inverse_is_consistent() {
        let n = order();
        for value in [[7u64, 0, 0, 0], [0xdeadbeef, 0x1234, 0, 0]] {
            assert_eq!(n.mul(&value, &n.invert(&value)), ONE);
        }
        // R^2 mod n 的往返：to_mont 之后乘 1 应当还原
        let value = [0x0123456789abcdefu64, 0xfedcba9876543210, 0, 0];
        assert_eq!(n.from_mont(&n.to_mont(&value)), value);
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
    }

    /// RFC 6979 附录 A.2.5：P-256 + SHA-256、"sample"、确定性 `k`。
    ///
    /// 这条向量是**独立来源**（不由本文件产出），所以它能证明整条 ECDSA 链路
    /// ——模 `n` 的乘/逆、`r` 的规约、`s` 的公式——而不只是"自己和自己一致"。
    #[test]
    fn ecdsa_matches_rfc6979_vector() {
        let d = from_hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .unwrap_or([0u8; 32]);
        let k = from_hex32("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60")
            .unwrap_or([0u8; 32]);
        let digest = sha256(b"sample");
        let signature = sign_with_k(&digest, &d, &k).unwrap_or([0u8; 64]);
        assert_eq!(
            crate::util::hex_lower(&signature[..32]),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "r 必须与 RFC 6979 A.2.5 一致"
        );
        assert_eq!(
            crate::util::hex_lower(&signature[32..]),
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            "s 必须与 RFC 6979 A.2.5 一致"
        );
    }

    #[test]
    fn rejects_out_of_range_scalars() {
        assert!(valid_scalar(&scalar(1)));
        assert!(!valid_scalar(&[0u8; 32]), "0 不是合法标量");
        assert!(!valid_scalar(&[0xffu8; 32]), "≥ n 不是合法标量");
        assert_eq!(public_key_sec1(&[0u8; 32]), None);
    }
}
