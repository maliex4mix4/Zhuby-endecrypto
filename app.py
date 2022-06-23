import hashlib
import streamlit as st
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode


class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]



def main():
    if "AES_instance" not in st.session_state:
        st.session_state.AES_instance = create_aes_instance("zhuby")
    dashboard(st.session_state.AES_instance)


def create_aes_instance(key):
    return AESCipher(key)


def encrypt_text(AES_instance, input_text):
    return AES_instance.encrypt(input_text)


def decrypt_text(AES_instance, input_text):
    return AES_instance.decrypt(input_text)


def dashboard(AES_instance):
    st.title("AES Data Security Demo")
    st.sidebar.title("Configurations")
    task = st.sidebar.radio("Task Type",
                            [
                                "Encrypt",
                                "Decrypt"])
    
    if task == "Encrypt":
        text_file = display(task)
        output_text = AES_instance.encrypt(text_file)
    elif task == "Decrypt":
        text_file = display(task)
        output_text = AES_instance.decrypt(text_file)

    if st.button("Run"):
        st.write("**Output Text**")
        st.write(output_text)
        st.download_button("Download output text", output_text)


def display(task):
    help_msg = f"You could either type in the text you want to {task.lower()} or\
        upload text files containing the sentences. The input sentence box, by default, \
        display the text in the files you upload. Feel free to modify it as needed."

    uploaded_file = upload(help_msg)
    if uploaded_file:
        text_file = st.text_area(f"Enter the text you want to {task.lower()} here",
                                 uploaded_file)
    else:
        text_file = st.text_area(f"Enter the text you want to {task.lower()} here")
    return text_file

    
def upload(help_msg, text="Upload a document here."):
    """Function to upload text files and return as string text
    params:
        text                    Display label for the upload button
        accept_multiple_files   params for the file_uploader function to accept more than a file
    returns:
        a string or a list of strings (in case of multiple files being uploaded)
    """
    with st.expander(text):
        uploaded_files = st.file_uploader(label="Upload text files only", 
                                          type="txt", help=help_msg)
        if st.button("Process"):
            if not uploaded_files:
                st.write("**No file uploaded!**")
                return None
            st.write("**Upload successful!**")
            return uploaded_files.read().decode("utf-8").strip()


if __name__ == "__main__":
    main()
