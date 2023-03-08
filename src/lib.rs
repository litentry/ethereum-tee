#![cfg_attr(not(feature = "std"), no_std)]
use bytes::BytesMut;
use codec::{Decode, Encode};
// Always use new!! This method should not be used for
pub use ecdsa_core::signature::Error as ecdsaError;

use ethereum::{
    EIP1559Transaction, EIP1559TransactionMessage, EIP2930Transaction, EIP2930TransactionMessage,
    EnvelopedEncodable, LegacyTransaction, LegacyTransactionMessage, TransactionSignature,
};

// TODO:: Implement decode
// use ethereum::{
//     EnvelopedDecodable, EnvelopedDecoderError,
// };
use ethereum_types::{H160, H256};
use k256::ecdsa::SigningKey;
// TODO: Do we need to implement this?
// use scale_info::TypeInfo;
use sha3::{Digest, Keccak256};
use sp_std::vec::Vec;
// There are three version of transaction
// 2023/3/2 Stay with EIP1559

// This type is for demonstrating purpose only
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct AccountPrivateKeyVC {
    user_id: u128,
    account_private_keys: Vec<AccountPrivateKey>,
}

// TODO: The key length should not be fixed
// This type is for demonstrating purpose only
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct AccountPrivateKey {
    chain_id: u64,
    signing_key: H256,
    public_key: H160,
}

// Using V2 for consistence with "package ethereum"
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionMessageV2 {
    /// Legacy transaction type
    Legacy(LegacyTransactionMessage),
    /// EIP-2930 transaction
    EIP2930(EIP2930TransactionMessage),
    /// EIP-1559 transaction
    EIP1559(EIP1559TransactionMessage),
}

impl EnvelopedEncodable for TransactionMessageV2 {
    fn type_id(&self) -> Option<u8> {
        match self {
            Self::Legacy(_) => None,
            Self::EIP2930(_) => Some(1),
            Self::EIP1559(_) => Some(2),
        }
    }

    fn encode_payload(&self) -> BytesMut {
        match self {
            Self::Legacy(tx_message) => rlp::encode(tx_message),
            Self::EIP2930(tx_message) => rlp::encode(tx_message),
            Self::EIP1559(tx_message) => rlp::encode(tx_message),
        }
    }
}

// TODO implement decode
// impl EnvelopedDecodable for TransactionMessageV2 {
//     /// Inner payload decoder error.
//     type PayloadDecoderError = DecoderError;

//     /// Decode raw bytes to a Self type.
//     fn decode(bytes: &[u8]) -> Result<Self, EnvelopedDecoderError<Self::PayloadDecoderError>> {
//         if bytes.is_empty() {
//             return Err(EnvelopedDecoderError::UnknownTypeId);
//         }

//         let first = bytes[0];

//         let rlp = Rlp::new(bytes);
//         if rlp.is_list() {
//             return Ok(Self::Legacy(rlp.as_val()?));
//         }

//         let s = &bytes[1..];

//         if first == 0x01 {
//             return Ok(Self::EIP2930(rlp::decode(s)?));
//         }

//         if first == 0x02 {
//             return Ok(Self::EIP1559(rlp::decode(s)?));
//         }

//         Err(DecoderError::Custom("invalid tx message type").into())
//     }
// }

// T: TransactionAction
// M: TransactionMessage
pub trait SignTransactionMessage<T, M> {
    fn sign_transaction(&self, txm: M) -> Result<T, ecdsaError>;
}

impl SignTransactionMessage<LegacyTransaction, LegacyTransactionMessage> for AccountPrivateKey {
    fn sign_transaction(
        &self,
        txm: LegacyTransactionMessage,
    ) -> Result<LegacyTransaction, ecdsaError> {
        let digest = Keccak256::new_with_prefix(rlp::encode(&txm));
        let signing_key = SigningKey::from_bytes(&(self.signing_key.0.into()))?;

        let (signature, recid) = signing_key.sign_digest_recoverable(digest)?;

        let v: u8 = 35u8
            + <u8 as Into<u8>>::into(recid.to_byte())
            + txm.chain_id.unwrap_or(0).try_into().unwrap_or(0) * 2u8;
        // r is the original signature after split
        let mut r = BytesMut::from(signature.to_bytes().as_slice());
        let s: BytesMut = r.split_off(32);

        let tx_signature = TransactionSignature::new(
            // Stupid dummy implementation
            v.into(),
            H256::from_slice(&r),
            H256::from_slice(&s),
        )
        .ok_or(ecdsaError::new())?;

        return Ok(LegacyTransaction {
            nonce: txm.nonce,
            gas_price: txm.gas_price,
            gas_limit: txm.gas_limit,
            action: txm.action,
            value: txm.value,
            input: txm.input,
            signature: tx_signature,
        });
    }
}

impl SignTransactionMessage<EIP2930Transaction, EIP2930TransactionMessage> for AccountPrivateKey {
    fn sign_transaction(
        &self,
        txm: EIP2930TransactionMessage,
    ) -> Result<EIP2930Transaction, ecdsaError> {
        let digest = Keccak256::new_with_prefix(rlp::encode(&txm));
        let signing_key = SigningKey::from_bytes(&(self.signing_key.0.into()))?;

        let (signature, recid) = signing_key.sign_digest_recoverable(digest)?;

        let v: u8 = 35u8
            + <u8 as Into<u8>>::into(recid.to_byte())
            + txm.chain_id.try_into().unwrap_or(0) * 2u8;
        // r is the original signature after split
        let mut r = BytesMut::from(signature.to_bytes().as_slice());
        let s: BytesMut = r.split_off(32);

        return Ok(EIP2930Transaction {
            chain_id: txm.chain_id,
            nonce: txm.nonce,
            gas_price: txm.gas_price,
            gas_limit: txm.gas_limit,
            action: txm.action,
            value: txm.value,
            input: txm.input,
            access_list: txm.access_list,
            // This is only the latest implementation of EIP-155
            // I do not think we should care other version
            v: v,
            r: H256::from_slice(&r),
            s: H256::from_slice(&s),
        });
    }
}

impl SignTransactionMessage<EIP1559Transaction, EIP1559TransactionMessage> for AccountPrivateKey {
    fn sign_transaction(
        &self,
        txm: EIP1559TransactionMessage,
    ) -> Result<EIP1559Transaction, ecdsaError> {
        let txm_rlp = rlp::encode(&txm);

        let mut txm_rlp_with_type_prefix = vec![0; 1 + txm_rlp.len()];
        txm_rlp_with_type_prefix[0] = 2;
        txm_rlp_with_type_prefix[1..].copy_from_slice(&txm_rlp);

        let digest = Keccak256::new_with_prefix(txm_rlp_with_type_prefix);
        let signing_key = SigningKey::from_bytes(&(self.signing_key.0.into()))?;

        let (signature, recid) = signing_key.sign_digest_recoverable(digest)?;

        // Even though EIP-155 has insist that v should be chain related, it seems most RPC endpoint still use plain recovery id
        let v: u8 = <u8 as Into<u8>>::into(recid.to_byte());
        // let v: u8 = 35u8 + <u8 as Into<u8>>::into(recid.to_byte()) + txm.chain_id.try_into().unwrap_or(0) * 2u8;
        // r is the original signature after split
        let mut r = BytesMut::from(signature.to_bytes().as_slice());
        let s: BytesMut = r.split_off(32);

        return Ok(EIP1559Transaction {
            chain_id: txm.chain_id,
            nonce: txm.nonce,
            max_priority_fee_per_gas: txm.max_priority_fee_per_gas,
            max_fee_per_gas: txm.max_fee_per_gas,
            gas_limit: txm.gas_limit,
            action: txm.action,
            value: txm.value,
            input: txm.input,
            access_list: txm.access_list,
            // This is only the latest implementation of EIP-155
            // I do not think we should care other version
            v: v,
            r: H256::from_slice(&r),
            s: H256::from_slice(&s),
        });
    }
}

// Return Raw RLP transaction
impl SignTransactionMessage<BytesMut, TransactionMessageV2> for AccountPrivateKey {
    fn sign_transaction(&self, txm: TransactionMessageV2) -> Result<BytesMut, ecdsaError> {
        let (type_id, tx_rlp) = match txm {
            TransactionMessageV2::Legacy(m) => {
                (None, rlp::encode(&self.sign_transaction(m).unwrap()))
            }
            TransactionMessageV2::EIP2930(m) => {
                (Some(1u8), rlp::encode(&self.sign_transaction(m).unwrap()))
            }
            TransactionMessageV2::EIP1559(m) => {
                (Some(2u8), rlp::encode(&self.sign_transaction(m).unwrap()))
            }
        };

        match type_id {
            None => Ok(tx_rlp),
            Some(n) if n < 3u8 => {
                let mut txm_rlp_with_type_prefix = vec![0u8; 1 + tx_rlp.len()];
                txm_rlp_with_type_prefix[0] = n;
                txm_rlp_with_type_prefix[1..].copy_from_slice(&tx_rlp);
                Ok(BytesMut::from(txm_rlp_with_type_prefix.as_slice()))
            }
            _ => Err(ecdsaError::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ethereum::TransactionAction;
    use hex_literal::hex;

    #[test]
    fn plain_transaction_message_encode_correctly() {
        // 0x297f658F438C9c657c45fd6B1b0dB4222f1983B0
        let account_public_key: H160 = hex!("297f658F438C9c657c45fd6B1b0dB4222f1983B0").into();
        // 0x297f658F438C9c657c45fd6B1b0dB4222f1983B0  's private key
        let account_private_key =
            hex!("7daadde6e9d1377640070b143cfbde103b078c008d35ee2c7ed989878f2187c7").into();

        // Goerli chain id=5, although it does not matter
        let apk = AccountPrivateKey {
            chain_id: 5,
            signing_key: account_private_key,
            public_key: account_public_key,
        };

        // https://goerli.etherscan.io/tx/0x37635b2ad4f83a84e5c16c727a662c7c2e16ea3ea272f5cfac1a44ec5de6fee4
        let txm = EIP1559TransactionMessage {
            chain_id: 5u64,
            nonce: 23.into(),
            max_priority_fee_per_gas: 1_500_000_000u64.into(),
            max_fee_per_gas: 20_000_000_000u64.into(),
            gas_limit: 31_524u64.into(),
            action: TransactionAction::Call(
                hex!("f8b27d2ffe5f01bc239eb058992af1c213c3d2ba").into(),
            ),
            value: 100_000_000_000_000_000u64.into(),
            input: hex!("11").into(),
            access_list: vec![],
        };

        // https://goerli.etherscan.io/getRawTx?tx=0x37635b2ad4f83a84e5c16c727a662c7c2e16ea3ea272f5cfac1a44ec5de6fee4
        let singed_raw_transaction_submitted = hex!("02f87305178459682f008504a817c800827b2494f8b27d2ffe5f01bc239eb058992af1c213c3d2ba88016345785d8a000011c080a02aba2bb292bdf5d7458f1fbf43a9dfa357e572a04230602a8ef0c322d48b05a5a063d675939d6de5e33d14c3c19a78f562b69e82a1db940f81c510ad3f43785665");

        //
        let singed_raw_transaction = Vec::from(Bytes::from(
            apk.sign_transaction(TransactionMessageV2::EIP1559(txm))
                .unwrap(),
        ));
        assert_eq!(
            hex::encode(singed_raw_transaction_submitted.as_slice()),
            hex::encode(singed_raw_transaction)
        );
        // assert_eq!(singed_raw_transaction_submitted.as_slice(), singed_raw_transaction);
    }
}
