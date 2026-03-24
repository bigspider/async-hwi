use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    ecdsa,
    hashes::Hash,
    psbt::Psbt,
    taproot::{self, TapLeafHash},
    XOnlyPublicKey,
};
use std::convert::TryFrom;
use tokio::sync::Mutex;

use vnd_bitcoin_client::{
    bip388, create_standalone_client, message, psbt_v0_to_v2, BitcoinClient, IdentityKey,
    IdentitySignature, ProofOfRegistration, RegistrationId, VAppTransport,
};

use vnd_bitcoin_common::psbt::{
    PsbtAccount, PsbtAccountCoordinates, PsbtAccountGlobalWrite, PsbtAccountInputWrite,
    PsbtAccountOutputWrite,
};

use crate::{utils, AddressScript, DeviceKind, Error as HWIError, CHANGE_INDEX, HWI, RECV_INDEX};

#[derive(Default)]
struct CommandOptions {
    wallet: Option<(
        String,
        message::Account,
        Option<[u8; 32]>,
        bip388::WalletPolicy,
    )>,
    display_xpub: bool,
}

pub struct Vanadium {
    client: Mutex<BitcoinClient>,
    options: CommandOptions,
}

impl std::fmt::Debug for Vanadium {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vanadium").finish()
    }
}

impl Vanadium {
    pub fn new(transport: Box<dyn VAppTransport + Send>) -> Self {
        Self {
            client: Mutex::new(BitcoinClient::new(transport)),
            options: CommandOptions::default(),
        }
    }

    pub fn display_xpub(mut self, display: bool) -> Self {
        self.options.display_xpub = display;
        self
    }

    pub fn with_wallet(
        mut self,
        name: impl Into<String>,
        policy: &str,
        hmac: Option<[u8; 32]>,
    ) -> Result<Self, HWIError> {
        let account = policy_to_account(policy)?;
        let wp = policy_to_bip388_wallet_policy(policy)?;
        self.options.wallet = Some((name.into(), account, hmac, wp));
        Ok(self)
    }

    /// Connect to a standalone V-App server.
    pub async fn try_connect(addr: Option<&str>) -> Result<Self, HWIError> {
        let transport = create_standalone_client(addr)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(Self::new(transport))
    }
}

impl From<Vanadium> for Box<dyn HWI + Send> {
    fn from(s: Vanadium) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

#[async_trait]
impl HWI for Vanadium {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::Vanadium
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let fpr = self
            .client
            .lock()
            .await
            .get_master_fingerprint()
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(Fingerprint::from(fpr.to_be_bytes()))
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let path_str = path.to_string();
        let (xpub_bytes, _) = self
            .client
            .lock()
            .await
            .get_extended_pubkey(&path_str, self.options.display_xpub, None)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Xpub::decode(&xpub_bytes).map_err(|_| HWIError::Device("Failed to decode xpub".to_string()))
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let account = policy_to_account(policy)?;
        let (_, por) = self
            .client
            .lock()
            .await
            .register_account(name, &account, None, None, true)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(Some(por.dangerous_as_bytes()))
    }

    async fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError> {
        if let Some((wallet_name, wallet_account, hmac, _)) = &self.options.wallet {
            let account = policy_to_account(policy)?;
            Ok(hmac.is_some() && name == wallet_name && account == *wallet_account)
        } else {
            Ok(false)
        }
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::Miniscript { index, change } => {
                let (name, account, hmac, _) = self
                    .options
                    .wallet
                    .as_ref()
                    .ok_or(HWIError::MissingPolicy)?;
                let por = hmac
                    .as_ref()
                    .map(|h| ProofOfRegistration::<bip388::WalletPolicy>::from_bytes(*h));
                let coords =
                    message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                        is_change: *change,
                        address_index: *index,
                    });
                self.client
                    .lock()
                    .await
                    .get_address(account, name, &coords, por.as_ref(), true, None)
                    .await
                    .map_err(|e| HWIError::Device(e.to_string()))?;
                Ok(())
            }
            AddressScript::P2TR(path) => {
                let children = utils::bip86_path_child_numbers(path.clone())?;
                let (hardened_children, normal_children) = children.split_at(3);
                let account_path = DerivationPath::from(hardened_children);
                let fg = self.get_master_fingerprint().await?;
                let xpub = self.get_extended_pubkey(&account_path).await?;
                let policy = format!("tr({}/**)", key_string_from_parts(fg, account_path, xpub));
                let account = policy_to_account(&policy)?;

                if ![RECV_INDEX, CHANGE_INDEX].contains(&normal_children[0]) {
                    return Err(HWIError::Bip86ChangeIndex);
                }
                let coords =
                    message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                        is_change: normal_children[0] == CHANGE_INDEX,
                        address_index: normal_children[1].into(),
                    });
                self.client
                    .lock()
                    .await
                    .get_address(&account, "", &coords, None, true, None)
                    .await
                    .map_err(|e| HWIError::Device(e.to_string()))?;
                Ok(())
            }
        }
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        if let Some((name, _, hmac, wp)) = &self.options.wallet {
            // Set global account info
            psbt.set_account(0, PsbtAccount::WalletPolicy(wp.clone()))
                .map_err(|e| HWIError::Device(format!("{:?}", e)))?;
            psbt.set_account_name(0, name)
                .map_err(|e| HWIError::Device(format!("{:?}", e)))?;
            if let Some(hmac) = hmac {
                psbt.set_account_proof_of_registration(0, hmac)
                    .map_err(|e| HWIError::Device(format!("{:?}", e)))?;
            }

            // For each key placeholder, find and set coordinates on matching inputs/outputs
            for (kp, _) in wp.descriptor_template.placeholders() {
                let key_info = &wp.key_information[kp.key_index as usize];
                let (fingerprint, origin_path_len) = match &key_info.origin_info {
                    Some(origin) => (
                        Fingerprint::from(origin.fingerprint.to_be_bytes()),
                        origin.derivation_path.len(),
                    ),
                    None => (key_info.pubkey.fingerprint(), 0),
                };

                for input in psbt.inputs.iter_mut() {
                    if let Some(coords) = get_wallet_policy_coordinates(
                        &input.bip32_derivation,
                        &input.tap_key_origins,
                        fingerprint,
                        origin_path_len,
                        kp,
                    ) {
                        input
                            .set_account_coordinates(
                                0,
                                PsbtAccountCoordinates::WalletPolicy(coords),
                            )
                            .map_err(|e| HWIError::Device(format!("{:?}", e)))?;
                    }
                }

                for output in psbt.outputs.iter_mut() {
                    if let Some(coords) = get_wallet_policy_coordinates(
                        &output.bip32_derivation,
                        &output.tap_key_origins,
                        fingerprint,
                        origin_path_len,
                        kp,
                    ) {
                        output
                            .set_account_coordinates(
                                0,
                                PsbtAccountCoordinates::WalletPolicy(coords),
                            )
                            .map_err(|e| HWIError::Device(format!("{:?}", e)))?;
                    }
                }
            }
        }

        let psbt_v0_bytes = Psbt::serialize(psbt);
        let psbt_v2_bytes =
            psbt_v0_to_v2(&psbt_v0_bytes).map_err(|e| HWIError::Device(e.to_string()))?;

        let sigs = self
            .client
            .lock()
            .await
            .sign_psbt(&psbt_v2_bytes)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;

        for sig in sigs {
            let input_idx = sig.input_index as usize;
            let input = psbt
                .inputs
                .get_mut(input_idx)
                .ok_or(HWIError::DeviceDidNotSign)?;

            if let Some(leaf_hash_bytes) = &sig.leaf_hash {
                // Tapscript signature
                if leaf_hash_bytes.len() != 32 {
                    return Err(HWIError::Device("Invalid leaf hash length".to_string()));
                }
                let mut leaf_hash_arr = [0u8; 32];
                leaf_hash_arr.copy_from_slice(leaf_hash_bytes);
                let leaf_hash = TapLeafHash::from_byte_array(leaf_hash_arr);
                let xonly_key = xonly_from_pubkey_bytes(&sig.pubkey)?;
                let tap_sig = taproot::Signature::from_slice(&sig.signature)
                    .map_err(|e| HWIError::Device(format!("Invalid tapscript sig: {}", e)))?;
                input
                    .tap_script_sigs
                    .insert((xonly_key, leaf_hash), tap_sig);
            } else if sig.signature.len() == 64 || sig.signature.len() == 65 {
                // Taproot key path signature
                let tap_sig = taproot::Signature::from_slice(&sig.signature)
                    .map_err(|e| HWIError::Device(format!("Invalid tap key sig: {}", e)))?;
                input.tap_key_sig = Some(tap_sig);
            } else {
                // ECDSA signature
                let pk = bitcoin::PublicKey::from_slice(&sig.pubkey)
                    .map_err(|e| HWIError::Device(format!("Invalid pubkey: {}", e)))?;
                let ecdsa_sig = ecdsa::Signature::from_slice(&sig.signature)
                    .map_err(|e| HWIError::Device(format!("Invalid ECDSA sig: {}", e)))?;
                input.partial_sigs.insert(pk, ecdsa_sig);
            }
        }

        Ok(())
    }

    async fn get_identity_key(&self, identity_index: u32) -> Result<Xpub, HWIError> {
        let xpub_bytes = self
            .client
            .lock()
            .await
            .get_identity_key(Some(identity_index), false)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Xpub::decode(&xpub_bytes).map_err(|_| HWIError::Device("Failed to decode xpub".to_string()))
    }

    async fn register_identity_key(
        &self,
        name: &str,
        key: &Xpub,
    ) -> Result<
        (
            RegistrationId<IdentityKey>,
            ProofOfRegistration<IdentityKey>,
        ),
        HWIError,
    > {
        let pubkey_bytes: [u8; 33] = key.public_key.serialize();
        Ok(self
            .client
            .lock()
            .await
            .register_identity_key(name, &pubkey_bytes)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?)
    }

    async fn get_signed_extended_pubkey(
        &self,
        path: &DerivationPath,
        identity_index: u32,
    ) -> Result<(Xpub, IdentitySignature), HWIError> {
        let path_str = path.to_string();
        let (xpub_bytes, sig) = self
            .client
            .lock()
            .await
            .get_extended_pubkey(&path_str, self.options.display_xpub, Some(identity_index))
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        let xpub = Xpub::decode(&xpub_bytes)
            .map_err(|_| HWIError::Device("Failed to decode xpub".to_string()))?;
        let sig = sig.ok_or(HWIError::DeviceDidNotSign)?;
        Ok((xpub, sig))
    }

    async fn get_signed_address(
        &self,
        script: &AddressScript,
        identity_index: u32,
    ) -> Result<(String, IdentitySignature), HWIError> {
        match script {
            AddressScript::Miniscript { index, change } => {
                let (name, account, hmac, _) = self
                    .options
                    .wallet
                    .as_ref()
                    .ok_or(HWIError::MissingPolicy)?;
                let por = hmac
                    .as_ref()
                    .map(|h| ProofOfRegistration::<bip388::WalletPolicy>::from_bytes(*h));
                let coords =
                    message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                        is_change: *change,
                        address_index: *index,
                    });
                let (address, sig) = self
                    .client
                    .lock()
                    .await
                    .get_address(
                        account,
                        name,
                        &coords,
                        por.as_ref(),
                        true,
                        Some(identity_index),
                    )
                    .await
                    .map_err(|e| HWIError::Device(e.to_string()))?;
                let sig = sig.ok_or(HWIError::DeviceDidNotSign)?;
                Ok((address, sig))
            }
            AddressScript::P2TR(path) => {
                let children = utils::bip86_path_child_numbers(path.clone())?;
                let (hardened_children, normal_children) = children.split_at(3);
                let account_path = DerivationPath::from(hardened_children);
                let fg = self.get_master_fingerprint().await?;
                let xpub = self.get_extended_pubkey(&account_path).await?;
                let policy = format!("tr({}/**)", key_string_from_parts(fg, account_path, xpub));
                let account = policy_to_account(&policy)?;

                if ![RECV_INDEX, CHANGE_INDEX].contains(&normal_children[0]) {
                    return Err(HWIError::Bip86ChangeIndex);
                }
                let coords =
                    message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                        is_change: normal_children[0] == CHANGE_INDEX,
                        address_index: normal_children[1].into(),
                    });
                let (address, sig) = self
                    .client
                    .lock()
                    .await
                    .get_address(&account, "", &coords, None, true, Some(identity_index))
                    .await
                    .map_err(|e| HWIError::Device(e.to_string()))?;
                let sig = sig.ok_or(HWIError::DeviceDidNotSign)?;
                Ok((address, sig))
            }
        }
    }

    async fn register_wallet_with_identities(
        &self,
        name: &str,
        policy: &str,
        registered_identities: Option<Vec<vnd_bitcoin_common::message::RegisteredIdentityEntry>>,
        key_signatures: Option<Vec<Option<vnd_bitcoin_common::message::IdentitySignature>>>,
    ) -> Result<
        (
            RegistrationId<vnd_bitcoin_common::bip388::WalletPolicy>,
            ProofOfRegistration<vnd_bitcoin_common::bip388::WalletPolicy>,
        ),
        HWIError,
    > {
        let account = policy_to_account(policy)?;
        Ok(self
            .client
            .lock()
            .await
            .register_account(name, &account, registered_identities, key_signatures, true)
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?)
    }
}

fn xonly_from_pubkey_bytes(pubkey: &[u8]) -> Result<XOnlyPublicKey, HWIError> {
    let slice = match pubkey.len() {
        32 => pubkey,
        33 => &pubkey[1..],
        _ => {
            return Err(HWIError::Device(
                "Invalid pubkey length for taproot sig".to_string(),
            ))
        }
    };
    XOnlyPublicKey::from_slice(slice)
        .map_err(|e| HWIError::Device(format!("Invalid x-only pubkey: {}", e)))
}

fn get_wallet_policy_coordinates(
    bip32_derivation: &std::collections::BTreeMap<
        bitcoin::secp256k1::PublicKey,
        bitcoin::bip32::KeySource,
    >,
    tap_key_origins: &std::collections::BTreeMap<
        XOnlyPublicKey,
        (Vec<TapLeafHash>, bitcoin::bip32::KeySource),
    >,
    fingerprint: Fingerprint,
    origin_path_len: usize,
    key_placeholder: &bip388::KeyPlaceholder,
) -> Option<message::WalletPolicyCoordinates> {
    for (_, (fpr, path)) in bip32_derivation.iter() {
        if *fpr != fingerprint || path.len() != origin_path_len + 2 {
            continue;
        }
        let change_step: u32 = path[path.len() - 2].into();
        let is_change = if change_step == key_placeholder.num1 {
            false
        } else if change_step == key_placeholder.num2 {
            true
        } else {
            continue;
        };
        let address_index: u32 = path[path.len() - 1].into();
        return Some(message::WalletPolicyCoordinates {
            is_change,
            address_index,
        });
    }

    for (_, (_, (fpr, path))) in tap_key_origins.iter() {
        if *fpr != fingerprint || path.len() != origin_path_len + 2 {
            continue;
        }
        let change_step: u32 = path[path.len() - 2].into();
        let is_change = if change_step == key_placeholder.num1 {
            false
        } else if change_step == key_placeholder.num2 {
            true
        } else {
            continue;
        };
        let address_index: u32 = path[path.len() - 1].into();
        return Some(message::WalletPolicyCoordinates {
            is_change,
            address_index,
        });
    }

    None
}

fn policy_to_bip388_wallet_policy(policy: &str) -> Result<bip388::WalletPolicy, HWIError> {
    let (template, key_strings) = utils::extract_keys_and_template::<String>(policy)?;
    let key_information: Vec<bip388::KeyInformation> = key_strings
        .iter()
        .map(|ks| bip388::KeyInformation::try_from(ks.as_ref()))
        .collect::<Result<_, _>>()
        .map_err(|_| HWIError::UnsupportedInput)?;
    bip388::WalletPolicy::new(&template, key_information).map_err(|_| HWIError::UnsupportedInput)
}

fn policy_to_account(policy: &str) -> Result<message::Account, HWIError> {
    let (template, key_strings) = utils::extract_keys_and_template::<String>(policy)?;
    let keys_info: Vec<message::PubkeyInfo> = key_strings
        .iter()
        .map(|ks| key_str_to_pubkey_info(ks.as_ref()))
        .collect::<Result<_, _>>()?;
    Ok(message::Account::WalletPolicy(message::WalletPolicy {
        template,
        keys_info,
    }))
}

fn key_str_to_pubkey_info(key_str: &str) -> Result<message::PubkeyInfo, HWIError> {
    let ki = bip388::KeyInformation::try_from(key_str).map_err(|_| HWIError::UnsupportedInput)?;
    Ok(message::PubkeyInfo {
        pubkey: ki.pubkey.encode().to_vec(),
        origin: ki.origin_info.map(|o| message::KeyOrigin {
            fingerprint: o.fingerprint,
            path: message::Bip32Path(o.derivation_path.iter().map(|c| u32::from(*c)).collect()),
        }),
    })
}

fn key_string_from_parts(fg: Fingerprint, path: DerivationPath, xpub: Xpub) -> String {
    format!(
        "[{}/{}]{}",
        fg,
        path.to_string().trim_start_matches("m/"),
        xpub
    )
}
