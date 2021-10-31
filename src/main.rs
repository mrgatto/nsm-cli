extern crate clap;
use aws_nitro_enclaves_cose as cose;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use nsm_io::{AttestationDoc, ErrorCode, Request, Response};
use serde_bytes::ByteBuf;
use serde_json::Value;

fn main() {
    let matches = App::new("nsm-cli")
        .version("0.1.0")
        .about("Nitro Security Module Cli")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("describe-nsm")
                .about("Returns capabilities and version of the connected NitroSecureModule"),
        ).subcommand(
            SubCommand::with_name("get-random")
                .about("Returns number of bytes of entropy"),
        ).subcommand(
            SubCommand::with_name("describe-pcr")
                .about("Read data from PlatformConfigurationRegister at some index")
                .arg(
                    Arg::with_name("index")
                        .short("i")
                        .long("index")
                        .required(true)
                        .takes_value(true)
                        .help("The PCR index (0..n)"),
                ),
        ).subcommand(
            SubCommand::with_name("attestation")
                .about("Create an AttestationDoc and sign it with it's private key to ensure authenticity")
                .arg(
                    Arg::with_name("userdata")
                        .short("d")
                        .long("userdata")
                        .required(false)
                        .takes_value(true)
                        .help("Additional user data"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("describe-pcr", Some(sub_m)) => describe_pcr(sub_m),
        ("describe-nsm", Some(_)) => describe_nsm(),
        ("get-random", Some(_)) => get_random(),
        ("attestation", Some(sub_m)) => attestation(sub_m),
        _ => {}
    };
}

fn describe_pcr(sub_matches: &ArgMatches) {
    let index_arg = sub_matches.value_of("index").unwrap();
    let index_arg = index_arg.parse::<u16>().unwrap();

    let nsm_fd = nsm_driver::nsm_init();

    let request = Request::DescribePCR { index: index_arg };
    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    let json = serde_json::to_value(&response).unwrap();
    if is_error(&json) {
        println!("{}", json);
    } else {
        println!("{}", json["DescribePCR"]);
    }

    nsm_driver::nsm_exit(nsm_fd);
}

fn describe_nsm() {
    let nsm_fd = nsm_driver::nsm_init();

    let request = Request::DescribeNSM {};
    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    let json = serde_json::to_value(&response).unwrap();
    if is_error(&json) {
        println!("{}", json);
    } else {
        println!("{}", json["DescribeNSM"]);
    }

    nsm_driver::nsm_exit(nsm_fd);
}

fn get_random() {
    let nsm_fd = nsm_driver::nsm_init();

    let request = Request::GetRandom {};
    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    let json = serde_json::to_value(&response).unwrap();
    if is_error(&json) {
        println!("{}", json);
    } else {
        println!("{}", json["GetRandom"]);
    }

    nsm_driver::nsm_exit(nsm_fd);
}

fn attestation(sub_matches: &ArgMatches) {
    let user_data = sub_matches.value_of("userdata").unwrap_or("");

    let nsm_fd = nsm_driver::nsm_init();

    let request = Request::Attestation {
        public_key: None,
        user_data: Some(ByteBuf::from(user_data)),
        nonce: None,
    };

    let response = match nsm_driver::nsm_process_request(nsm_fd, request) {
        Response::Attestation { document } => Ok(document),
        Response::Error(err) => Err(err),
        _ => Err(ErrorCode::InvalidResponse),
    };

    if response.is_err() {
        let json = serde_json::to_string(&response.unwrap_err());
        println!("{:?}", json.unwrap());
    } else {
        let cbor = response.unwrap() as Vec<u8>;
        let attestation_doc = attestation_decode(&cbor);
        let json = serde_json::to_string(&attestation_doc);
        println!("{:?}", json.unwrap());
    }

    nsm_driver::nsm_exit(nsm_fd);
}

fn attestation_decode(cbor: &Vec<u8>) -> AttestationDoc {
    let cose_doc = cose::CoseSign1::from_bytes(cbor).unwrap();
    let payload = cose_doc.get_payload(None).unwrap();

    AttestationDoc::from_binary(&payload).unwrap()
}

fn is_error(json_value: &Value) -> bool {
    !json_value["Error"].is_null()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_attestation_decode() {
        let doc = &std::fs::read_to_string("data/attestation_doc_bytes").unwrap();

        let cbor: Vec<u8> = doc
            .split(',')
            .into_iter()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| x.parse::<u8>().unwrap())
            .collect();

        let attestation_doc = attestation_decode(&cbor.to_vec());
        assert_eq!(
            attestation_doc.module_id,
            "i-09eb1f8c065b7f2e8-enc017c9014e72f9d78"
        );
        //println!("{:?}", attestation_doc);
    }
}
