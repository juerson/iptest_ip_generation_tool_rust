use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Write},
    net::Ipv4Addr,
    str::FromStr,
};

fn main() -> io::Result<()> {
    let input_cidr = get_user_input_cidr()?;
    println!("——————————————————————————————————————————————————————————————————————————————");
    let ports: Vec<u16> = vec![80, 8080, 8880, 2052, 2082, 2086, 2095];
    let tls_ports: Vec<u16> = vec![443, 2053, 2083, 2087, 2096, 8443];
    let selected_ports_vec = selected_ports_vec(&ports, &tls_ports);
    println!("——————————————————————————————————————————————————————————————————————————————");
    println!("数据正在生成...");
    let ips = cidr_to_ips(&input_cidr);
    let ip_with_ports = add_ports_to_ips(ips, &selected_ports_vec);
    println!(
        "生成 {} 个'IP PORT'地址(1个IP -> 1个PORT，不存在同一个IP —> 多个PORT)",
        ip_with_ports.len()
    );
    println!("——————————————————————————————————————————————————————————————————————————————");
    // 打乱数据后，写入前1000个数据到文件中
    write_ips_to_file(ip_with_ports, "ip.txt", 1000)
}

fn get_user_input_cidr() -> Result<String, io::Error> {
    let cidr_regex = Regex::new(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$").unwrap();
    let mut cidr = String::new();
    let input_cidr = loop {
        print!("请输入一个 IPv4 CIDR (e.g., 104.16.0.0/12):");
        // 刷新缓存区
        io::stdout().flush()?;
        cidr.clear();
        io::stdin().read_line(&mut cidr)?;
        let cidr = cidr.trim();

        if cidr_regex.is_match(cidr) {
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip_part = parts[0];
            let prefix_str = parts[1];
            // 确保字符串中只包含数字字符
            if !prefix_str.chars().all(|c| c.is_digit(10)) {
                continue;
            }

            let prefix_length: u8 = match prefix_str.parse() {
                Ok(num) => num,
                Err(_) => {
                    println!("Failed to parse prefix length. Please try again.");
                    continue;
                }
            };

            let ip_octets: Vec<&str> = ip_part.split('.').collect();
            if ip_octets.len() == 4
                && ip_octets.iter().all(|&octet| octet.parse::<u8>().is_ok())
                && prefix_length <= 32
            {
                break cidr.to_string();
            }
        }
    };
    Ok(input_cidr)
}

fn selected_ports_vec<'a>(ports: &'a Vec<u16>, tls_ports: &'a Vec<u16>) -> &'a Vec<u16> {
    let selected_ports_vec: &Vec<u16>;
    println!("亲，选择哪组端口随机生成呢？输入对应的数字1、2即可！");
    println!("1. 选择非TLS的端口：{:?}", ports);
    println!("2. 选择是TLS的端口：{:?}", tls_ports);
    loop {
        print!("这里输入您选择的数字: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        // 去除换行符并转换为整数
        let choice: u32 = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                continue;
            }
        };
        // 根据用户选择返回对应的 Vec<u16>
        selected_ports_vec = match choice {
            1 => &ports,
            2 => &tls_ports,
            _ => {
                continue;
            }
        };
        break;
    }
    selected_ports_vec
}

fn cidr_to_ips(cidr: &str) -> Vec<Ipv4Addr> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        panic!("Invalid CIDR format");
    }
    let base_ip = Ipv4Addr::from_str(parts[0]).expect("Invalid IP address format");
    let prefix_length: u32 = match parts[1].parse() {
        Ok(num) => num,
        Err(err) => {
            panic!("Failed to parse prefix length: {}", err);
        }
    };

    let base_ip_u32: u32 = u32::from(base_ip);
    let netmask = (!0u32).checked_shl(32 - prefix_length).unwrap_or(0);
    let network = base_ip_u32 & netmask;
    let broadcast = network | !netmask;

    let mut ip_set = HashSet::new();
    for ip in network..=broadcast {
        let ip_addr = Ipv4Addr::from(ip);
        let octets = ip_addr.octets();
        if octets[3] != 0 && octets[3] != 255 {
            ip_set.insert(ip_addr);
        }
    }

    let mut ips: Vec<Ipv4Addr> = ip_set.into_iter().collect();

    // Shuffle the IP addresses
    let mut rng = thread_rng();
    ips.shuffle(&mut rng);

    ips
}

fn add_ports_to_ips(ips: Vec<Ipv4Addr>, ports: &[u16]) -> Vec<String> {
    let mut rng = thread_rng();
    let mut ip_with_ports = Vec::new();

    for ip in ips {
        let port = ports.choose(&mut rng).expect("Ports vector is empty");
        ip_with_ports.push(format!("{} {}", ip, port));
    }

    ip_with_ports
}

fn write_ips_to_file(
    ip_with_ports: Vec<String>,
    filename: &str,
    max_lines: usize,
) -> io::Result<()> {
    let mut rng = thread_rng();
    let mut shuffled_ips = ip_with_ports.clone();
    shuffled_ips.shuffle(&mut rng);

    let selected_ips = if shuffled_ips.len() > max_lines {
        &shuffled_ips[..max_lines]
    } else {
        &shuffled_ips
    };

    let mut file = File::create(filename)?;
    for ip_port in selected_ips {
        writeln!(file, "{}", ip_port)?;
    }
    println!(
        "已经写入前 {} 个'IP PORT'地址到 {} 文件中！",
        selected_ips.len(),
        filename
    );

    Ok(())
}
