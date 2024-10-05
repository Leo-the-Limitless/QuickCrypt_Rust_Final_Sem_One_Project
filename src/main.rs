use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex::{decode, encode};
use iced::widget::{Button, Column, Row, Container, Text, TextInput};
use iced::{executor, Alignment, Application, Command, Element, Length, Settings, Theme, clipboard};
use rand::Rng;
use std::fs::{read, write};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct FileEncryptionTool {
    file_path: String,
    key: String,
    iv: String,
    status_message: String,
}

#[derive(Debug, Clone)]
enum Message {
    FilePathChanged(String),
    KeyChanged(String),
    IvChanged(String),
    EncryptFile,
    DecryptFile,
    SelectFile,
    GenerateKey,
    GenerateIv,
    CopyKeyToClipboard,
    CopyIvToClipboard,
}

impl Application for FileEncryptionTool {
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();
    type Theme = Theme;

    fn new(_flags: ()) -> (Self, Command<Self::Message>) {
        (
            FileEncryptionTool {
                file_path: String::new(),
                key: String::new(),
                iv: String::new(),
                status_message: String::from("Ready"),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("File Encryption Tool")
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::FilePathChanged(new_path) => {
                self.file_path = new_path;
            }
            Message::KeyChanged(new_key) => {
                self.key = new_key;
            }
            Message::IvChanged(new_iv) => {
                self.iv = new_iv;
            }
            Message::EncryptFile => {
                if self.file_path.is_empty() || self.key.is_empty() || self.iv.is_empty() {
                    self.status_message = "Please enter file path, key, and IV.".to_string();
                } else {
                    if let Err(e) = self.encrypt_file() {
                        self.status_message = format!("Encryption failed: {}", e);
                    } else {
                        self.status_message = String::from("File successfully encrypted.");
                    }
                }
            }
            Message::DecryptFile => {
                if self.file_path.is_empty() || self.key.is_empty() || self.iv.is_empty() {
                    self.status_message = "Please enter file path, key, and IV.".to_string();
                } else {
                    if let Err(e) = self.decrypt_file() {
                        self.status_message = format!("Decryption failed: {}", e);
                    } else {
                        self.status_message = "File successfully decrypted.".to_string();
                    }
                }
            }
            Message::SelectFile => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.file_path = path.display().to_string();
                    self.status_message = format!("File selected: {}", self.file_path);
                } else {
                    self.status_message = String::from("No file selected.");
                }
            }
            Message::GenerateKey => {
                self.key = FileEncryptionTool::generate_random_key();
                self.status_message = String::from("Key generated.");
            }
            Message::GenerateIv => {
                self.iv = FileEncryptionTool::generate_random_iv();
                self.status_message = String::from("IV generated.");
            }
            Message::CopyKeyToClipboard => {
                if self.key.is_empty() {
                    self.status_message = "Key field is empty, nothing to copy.".to_string();
                } else {
                    self.status_message = "Key has been copied.".to_string();
                    return clipboard::write(self.key.clone());
                }
            }
            Message::CopyIvToClipboard => {
                if self.iv.is_empty() {
                    self.status_message = "IV field is empty, nothing to copy.".to_string();
                } else {
                    self.status_message = "IV has been copied.".to_string();
                    return clipboard::write(self.iv.clone());
                }
            }
        }

        Command::none()
    }

    fn view(&self) -> Element<Self::Message> {
        // File Path Input
        let file_input = TextInput::new(
            "Enter the file path...", 
            &self.file_path
        )
        .padding(10)
        .width(Length::Fixed(400.0))  // Widening input fields for more breathing room
        .on_input(Message::FilePathChanged);

        // Key Input
        let key_input = TextInput::new(
            "Enter encryption key...", 
            &self.key
        )
        .padding(10)
        .width(Length::Fixed(400.0))  // Same width for all inputs
        .on_input(Message::KeyChanged);

        // IV Input
        let iv_input = TextInput::new(
            "Enter initialization vector...", 
            &self.iv
        )
        .padding(10)
        .width(Length::Fixed(400.0))
        .on_input(Message::IvChanged);

        let content = Column::new()
            .padding(20)
            .align_items(Alignment::Center)
            .spacing(15)  // Increased spacing between elements for readability
            .push(file_input)
            .push(
                Row::new()
                    .spacing(10)
                    .push(Button::new(Text::new("Generate Key")).on_press(Message::GenerateKey))
                    .push(Button::new(Text::new("Generate IV")).on_press(Message::GenerateIv)),
            )
            .push(key_input)
            .push(
                Row::new()
                    .spacing(10)
                    .push(Button::new(Text::new("Copy Key")).on_press(Message::CopyKeyToClipboard))
                    .push(Button::new(Text::new("Copy IV")).on_press(Message::CopyIvToClipboard)),
            )
            .push(iv_input)
            .push(
                Row::new()
                    .spacing(10)
                    .push(Button::new(Text::new("Encrypt")).on_press(Message::EncryptFile))
                    .push(Button::new(Text::new("Decrypt")).on_press(Message::DecryptFile))
                    .push(Button::new(Text::new("Select File")).on_press(Message::SelectFile)),
            )
            .push(Text::new(&self.status_message).size(16));  

        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

}

impl FileEncryptionTool {
    fn encrypt_file(&self) -> Result<(), String> {
        let key = decode(&self.key).map_err(|_| "Invalid key format")?;
        let iv = decode(&self.iv).map_err(|_| "Invalid IV format")?;

        let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Invalid key/IV length")?;
        let data = read(&self.file_path).map_err(|_| "Failed to read file")?;
        let ciphertext = cipher.encrypt_vec(&data);
        let encrypted_file_path = format!("{}.enc", self.file_path);
        write(&encrypted_file_path, &ciphertext).map_err(|_| "Failed to write encrypted file")?;

        Ok(())
    }

    fn decrypt_file(&self) -> Result<(), String> {
        let key = decode(&self.key).map_err(|_| "Invalid key format")?;
        let iv = decode(&self.iv).map_err(|_| "Invalid IV format")?;

        let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Invalid key/IV length")?;
        let mut encrypted_data = read(&self.file_path).map_err(|_| "Failed to read file")?;
        let decrypted_data = cipher.decrypt_vec(&mut encrypted_data).map_err(|_| "Failed to decrypt file")?;
        
        let decrypted_file_path = if self.file_path.ends_with(".enc") {
            let trimmed_file_path = self.file_path.trim_end_matches(".enc");
            if let Some(pos) = trimmed_file_path.rfind('.') {
                let (base, ext) = trimmed_file_path.split_at(pos);
                format!("{}_decrypted{}", base, ext)
            } else {
                format!("{}_decrypted", trimmed_file_path)
            }
        } else {
            format!("{}_decrypted", self.file_path)
        };

        write(&decrypted_file_path, &decrypted_data).map_err(|_| "Failed to write decrypted file")?;

        Ok(())
    }

    fn generate_random_key() -> String {
        let key: [u8; 32] = rand::thread_rng().gen();
        encode(key)
    }

    fn generate_random_iv() -> String {
        let iv: [u8; 16] = rand::thread_rng().gen();
        encode(iv)
    }
}

fn main() -> iced::Result {
    FileEncryptionTool::run(Settings::default())
}