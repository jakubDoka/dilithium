use rand_core::{CryptoRng, RngCore};

use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair
{
  pub public: [u8; PUBLICKEYBYTES],
  secret: [u8; SECRETKEYBYTES],
}

/// Secret key elided
#[cfg(feature = "std")]
impl std::fmt::Debug for Keypair
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError
{
  Input,
  Verify,
}

impl Keypair
{
  /// Explicitly expose secret key
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// let secret_key = keys.expose_secret();
  /// assert!(secret_key.len() == SECRETKEYBYTES);
  /// ```
  pub fn expose_secret(&self) -> &[u8]
  {
    &self.secret
  }

  /// Generates a keypair for signing and verification
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// let keys = Keypair::generate();
  /// assert!(keys.public.len() == PUBLICKEYBYTES);
  /// assert!(keys.expose_secret().len() == SECRETKEYBYTES);
  /// ```
  #[cfg(feature = "getrandom")]
  pub fn generate() -> Keypair
  {
    use rand_core::OsRng;

    Self::generate_with(OsRng)
  }

  pub fn generate_with(rng: impl RngCore + CryptoRng) -> Keypair
  {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, rng);
    Keypair { public, secret }
  }

  /// Generates a signature for the given message using a keypair
  ///
  /// Example:
  /// ```
  /// # use pqc_dilithium::*;
  /// # let keys = Keypair::generate();
  /// let msg = "Hello".as_bytes();
  /// let sig = keys.sign(&msg);
  /// assert!(sig.len() == SIGNBYTES);
  /// ```
  #[cfg(feature = "getrandom")]
  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES]
  {
    use rand_core::OsRng;

    self.sign_with(msg, OsRng)
  }

  pub fn sign_with(
    &self,
    msg: &[u8],
    rng: impl RngCore + CryptoRng,
  ) -> [u8; SIGNBYTES]
  {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret, rng);
    sig
  }
}

/// Verify signature using keypair
///
/// Example:
/// ```
/// # use pqc_dilithium::*;
/// # let keys = Keypair::generate();
/// # let msg = [0u8; 32];
/// # let sig = keys.sign(&msg);
/// let sig_verify = verify(&sig, &msg, &keys.public);
/// assert!(sig_verify.is_ok());
pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError>
{
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}
