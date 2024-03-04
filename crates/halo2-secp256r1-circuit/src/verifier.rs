#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Circuit, Error};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use rand::rngs::OsRng;
use snark_verifier::loader::evm::ExecutorBuilder;
use snark_verifier::util::arithmetic::PrimeField;

use crate::{cal_row_size, Secp256r1Circuit};

pub struct Secp256r1Verifier<const N: usize> {
    pub keygen_circuit: Secp256r1Circuit<Fr, N>,
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
}

#[derive(Debug)]
pub struct Secp256r1VerifyResult {
    pub success: bool,
    pub gas_used: u64,
}

impl<const N: usize> Secp256r1Verifier<N> {
    pub fn new(k: u32) -> Result<Self, Error> {
        let circuit = Secp256r1Circuit::<Fr, N>::default();
        let params = Self::gen_params(k);

        #[cfg(feature = "display")]
        let pt = start_timer!(|| "keygen_vk");

        let vk = keygen_vk(&params, &circuit)?;

        #[cfg(feature = "display")]
        end_timer!(pt);

        #[cfg(feature = "display")]
        let pt = start_timer!(|| "keygen_pk");

        let pk = keygen_pk(&params, vk, &circuit)?;

        #[cfg(feature = "display")]
        end_timer!(pt);

        Ok(Secp256r1Verifier {
            keygen_circuit: circuit,
            params,
            pk,
        })
    }

    pub fn deployment_code(&self) -> Vec<u8> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "create deployment code");

        let params_size = cal_row_size(160, Fr::NUM_BITS as usize / 8) + 1;
        let num_instance: Vec<usize> = vec![N * params_size];
        let deployment_code = snark_verifier_sdk::gen_evm_verifier_shplonk::<Secp256r1Circuit<Fr, N>>(
            &self.params,
            self.pk.get_vk(),
            num_instance,
            None,
        );

        #[cfg(feature = "display")]
        end_timer!(pt);
        deployment_code
    }

    pub fn gen_params(k: u32) -> ParamsKZG<Bn256> {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "setup params");

        let params = ParamsKZG::<Bn256>::setup(k, OsRng);

        #[cfg(feature = "display")]
        end_timer!(pt);

        params
    }

    pub fn evm_verify(&self, instances: Vec<Fr>, proof: &[u8]) -> Secp256r1VerifyResult {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build();
        let caller = Default::default();
        let deployment_code = self.deployment_code();
        let contract = evm
            .deploy(caller, deployment_code.into(), 0.into())
            .address
            .unwrap();

        let calldata = self.generate_calldata(instances, proof);
        let result = evm.call_raw(caller, contract, calldata.into(), 0.into());
        Secp256r1VerifyResult {
            success: !result.reverted,
            gas_used: result.gas_used,
        }
    }

    pub fn from_bytes(mut buf: &[u8], format: SerdeFormat) -> Option<Self> {
        type C<const N: usize> = Secp256r1Circuit<Fr, N>;
        let r = &mut buf;
        let params = ParamsKZG::read_custom(r, format).ok()?;
        let pk = ProvingKey::read::<_, C<N>>(r, format).ok()?;
        Some(Self { keygen_circuit: C::default(), params, pk })
    }

    pub fn to_bytes(&self, format: SerdeFormat) -> Vec<u8> {
        let mut buf = vec![];
        self.params.write_custom(&mut buf, format).unwrap();
        buf.extend(self.pk.to_bytes(format));
        buf
    }

    pub fn generate_proof<C>(&self, circuit: C, instances: Vec<Fr>) -> Vec<u8>
    where
        C: Circuit<Fr>,
    {
        #[cfg(feature = "display")]
        let pt = start_timer!(|| "generate proof");

        let proof = snark_verifier_sdk::gen_evm_proof_shplonk(
            &self.params,
            &self.pk,
            circuit,
            vec![instances],
            &mut OsRng,
        );

        #[cfg(feature = "display")]
        end_timer!(pt);

        proof
    }

    pub fn generate_calldata(&self, instances: Vec<Fr>, proof: &[u8]) -> Vec<u8> {
        snark_verifier_sdk::encode_calldata(&[instances], &proof)
    }
}
