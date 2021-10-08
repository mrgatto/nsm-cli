extern crate clap;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use nsm_io::Request;

fn main() {
    let matches = App::new("nsm-cli")
        .version("0.1.0")
        .about("Nitro Security Module Cli")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("describe-nsm")
                .about("Return capabilities and version of the connected NitroSecureModule"),
        )
        .subcommand(
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
        )
        .get_matches();

    match matches.subcommand() {
        ("describe-pcr", Some(sub_m)) => describe_pcr(sub_m),
        ("describe-nsm", Some(_)) => describe_nsm(),
        _ => {}
    }
}

fn describe_pcr(sub_matches: &ArgMatches) {
    let index_arg = sub_matches.value_of("index").unwrap();
    let index_arg = index_arg.parse::<u16>().unwrap();

    let nsm_fd = nsm_driver::nsm_init();
    let request = Request::DescribePCR { index: index_arg };

    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    let json = serde_json::to_string(&response);
    println!("{:?}", json.unwrap());

    nsm_driver::nsm_exit(nsm_fd);
}

fn describe_nsm() {
    let nsm_fd = nsm_driver::nsm_init();

    let request = Request::DescribeNSM {};
    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    let json = serde_json::to_string(&response);
    println!("{:?}", json.unwrap());

    nsm_driver::nsm_exit(nsm_fd);
}
