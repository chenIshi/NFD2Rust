#[derive(Debug)]
pub enum Command {
    FileReadCommand(String, Option<String>),
    RunInlineCode(String, Option<String>),
    Noop,
}

pub fn read_command() -> Command {
    let matches = clap_app!(
        nfd2rust =>     (version: "0.1.0")
                        (author: "chenishi <chen.ishi@gmail.com>")
                        (about: "NFD to Rust Compiler")
                        (@setting ArgRequiredElseHelp)
                        (@arg src: -s --src +takes_value "Path of the source file")
                        (@arg run: -r --run +takes_value "Code you want to run inline")
                        (@arg net: -n --net +takes_value "Network Interface Currently Availale")
    ).get_matches();

    let src_path = matches.value_of("src").map(|s| s.to_string());
    let run_string = matches.value_of("run").map(|s| s.to_string());
    let net_interface = matches.value_of("net").map(|s| s.to_string());
    match (src_path, run_string) {
        (Some(s), _) => Command::FileReadCommand(s, net_interface),
        (_, Some(s)) => Command::RunInlineCode(s, net_interface),
        _ => Command::Noop,
    }
}