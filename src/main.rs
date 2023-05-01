mod signatures;
use vt3::VtClient;
use std::env;
use std::io;
use std::io::Read;
use std::fs::File;

fn main() {
    // menu();
    let args : Vec<String> = env::args().collect();
    if args.len() != 3 {
        help_menu();
        std::process::exit(1);
    }
    let opt = &args[1];
    let val = &args[2];
    banner_art();
    let api_key = get_api_key();
    println!("\nVirusTotal API key : {}", hidden_api_key(api_key.as_str()));
    if opt == "--ip-info" {
        ip_info(val.as_str(), api_key.as_str());
    } else if opt == "--url-info" {
        url_scan(val.as_str(), api_key.as_str());
    } else if opt == "--file-scan" {
        file_scan(val.as_str(), api_key.as_str()); 
    } else {
        println!("Invalid option {}", opt);
    }
}

fn get_api_key() -> String {
    let api_key = match env::var("VIRUSTOTAL_API_KEY") {
        Ok(api_key) => api_key,
        Err(e) => {
            println!("\x1B[1;31m${} is not set ({}) \x1B[0m", "VIRUSTOTAL_API_KEY", e);
            std::process::exit(1);
        },
    };
    let result = api_key.to_string();
    return result
}

fn ip_info(ip_address : &str, api_key : &str) { 
    let res = VtClient::new(api_key).ip_info(ip_address);
    match res {
        Ok(report) => { 
           if let Some(attributes) = report.data.attributes {
                println!("\nIP address Information :-");
                println!("\x1B[1;34mRIR : {}", attributes.regional_internet_registry.unwrap());
                println!("Network : {}", attributes.network.unwrap());
                println!("Country : {}", attributes.country.unwrap());
                println!();
            } else {
                println!("No attributes found for this IP address.");
            }
        },
        Err(e) => println!("Error : {}", e.to_string()),
    }
}

fn url_scan(url : &str, api_key : &str) {
    let res = VtClient::new(api_key).url_info(url);
    match res {
        Ok(report) => {
            println!("\nURL Information :-");
            println!("{:#?}", report);
        },
        Err(e) => println!("Error : {}", e.to_string()),
    }
}

fn file_scan(file_path : &str, api_key : &str) {
    let mut file_handle = File::open(file_path)
        .expect("Unable to read file");
    let mut buffer = [0u8; 4];
    file_handle.read_exact(&mut buffer).expect("Failed");
    let file_header = buffer.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    signatures::check_signature(file_header.as_str());
}

fn banner_art() {
    let banner = "
     __  ___      __                  __                     
    /  |/  /___ _/ /___ _____  ____ _/ /_  ______  ___  _____
   / /|_/ / __ `/ / __ `/ __ \\/ __ `/ / / / /_  / / _ \\/ ___/
  / /  / / /_/ / / /_/ / / / / /_/ / / /_/ / / /_/  __/ /    
 /_/  /_/\\__,_/_/\\__,_/_/ /_/\\__,_/_/\\__, / /___/\\___/_/     v0.1.0
                                    /____/                          
            nxb1t || mrsh4n                                        ";

    let pretty_banner = format!(
        "{}{}{}",
        "\x1B[1;34m", // set color to bright red
        banner,
        "\x1B[0m", // reset color
    );    
    println!("{}", pretty_banner);
}

fn help_menu() {
    println!("Usage : malanalyzer [OPTION] [VALUE]");
    println!("Make sure to export your VirusTotal API key in VIRUSTOTAL_API_KEY environment variable");
    println!("Available Options :- ");
    println!("     --ip-info    :  Scan IP address for Malicious behaviours");
    println!("                     Eg :- malanalyzer --ip-info 1.1.1.1 \n");
    println!("     --url-info   :  Scan URL for Malicious behaviours");
    println!("                     Eg :- malanalyzer --url-info https://google.com\n");
}

fn hidden_api_key(key : &str) -> String {
   format!("{}{}{}", &key[0..4], "*".repeat(key.len() - 8), &key[key.len() - 4..]) 
}
