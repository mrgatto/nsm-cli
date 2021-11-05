use aws_nitro_enclaves_cose as cose;
use nsm_io::AttestationDoc;
use openssl::x509::X509;
use serde_json::Value;

fn main() {
    let doc = &std::fs::read_to_string("../../data/attestation_doc_raw.json").unwrap();

    let json_value: Value = serde_json::from_str(doc).unwrap();
    let cbor_field = json_value.get("cbor").unwrap();

    let cbor: Vec<u8> = cbor_field
        .as_array()
        .unwrap()
        .into_iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();

    let cose_doc = cose::CoseSign1::from_bytes(&cbor).unwrap();
    let cose_payload = cose_doc.get_payload(None).unwrap();
  
    let attestation_doc = AttestationDoc::from_binary(&cose_payload).unwrap();
    let cert = X509::from_der(&attestation_doc.certificate).unwrap();

    let signature_valid = cose_doc
        .verify_signature(&cert.public_key().unwrap())
        .unwrap();

    println!("Valid COSE signed message?: {}", signature_valid);

    // TODO validate root certificate
}
