use std::collections::HashMap;

fn signatures_db() -> HashMap<String, String> {
    let mut db = HashMap::new();
    db.insert("504B0304".to_string(), "zip".to_string());
    db.insert("25504446".to_string(), "pdf".to_string());
    db.insert("7F454C46".to_string(), "elf".to_string());
    db.insert("52617221".to_string(), "rar".to_string());
    db.insert("504B0304".to_string(), "msoffice document".to_string());
    db.insert("4D5A9000".to_string(), "exe".to_string());
    db
}

pub fn check_signature(magic_byte : &str) {
    let signatures = signatures_db();
    match signatures.get(magic_byte) {
        Some(signature) => println!("File type : {}", signature),
        None => println!("File type : Unknown , Magic : {}", magic_byte),
    }
}
