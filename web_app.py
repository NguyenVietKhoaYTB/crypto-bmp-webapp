# web_app.py
import streamlit as st
import os
import sys
from PIL import Image
import io

# Thêm đường dẫn hiện tại vào sys.path để import các module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from crypto_utils import encrypt_bytes, decrypt_bytes
    from image_utils import read_bmp, write_bmp
except ImportError as e:
    st.error(f"Lỗi import module: {e}")
    st.stop()

st.set_page_config(page_title="🔐 Web App Mã Hóa BMP", layout="wide")
st.title("🔐 Web App Mã Hóa BMP")
st.write("Ứng dụng mã hóa/giải mã ảnh BMP bằng AES, được tạo bởi Nguyễn Việt Khoa YTB")

# Upload file
uploaded_file = st.file_uploader("Chọn file BMP", type=["bmp"])

if uploaded_file is not None:
    try:
        # Lưu file tạm để đọc
        with open("temp_upload.bmp", "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Hiển thị ảnh gốc
        st.image("temp_upload.bmp", caption="Ảnh gốc", use_column_width=True)
        
        # Chọn chế độ
        mode = st.selectbox("Chọn chế độ mã hóa", ["ECB", "CBC", "CFB", "OFB", "CTR"])
        
        # Nhập key
        key_input = st.text_input("Nhập key (hex hoặc text)", value="mysecretkey")
        
        # Nhập IV (nếu cần)
        if mode != "ECB":
            iv_input = st.text_input("Nhập IV (hex hoặc text)", value="")
        else:
            iv_input = ""
        
        # Nút mã hóa và giải mã
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔒 Mã Hóa", key="encrypt_btn"):
                try:
                    # Đọc file BMP
                    header, pixels = read_bmp("temp_upload.bmp")
                    
                    # Mã hóa
                    ciphertext, actual_iv = encrypt_bytes(pixels, key_input, mode, iv_input if iv_input else None)
                    
                    # Lưu file đã mã hóa
                    output_path = "encrypted.bmp"
                    write_bmp(output_path, header, ciphertext)
                    
                    # Hiển thị kết quả
                    st.success("Mã hóa thành công!")
                    st.image(output_path, caption="Ảnh đã mã hóa", use_column_width=True)
                    
                    # Download button
                    with open(output_path, "rb") as file:
                        st.download_button(
                            label="📥 Tải ảnh đã mã hóa",
                            data=file,
                            file_name="encrypted.bmp",
                            mime="image/bmp"
                        )
                    
                    if actual_iv:
                        st.info(f"IV được sử dụng: {actual_iv.hex()}")
                        
                except Exception as e:
                    st.error(f"Lỗi khi mã hóa: {str(e)}")
        
        with col2:
            if st.button("🔓 Giải Mã", key="decrypt_btn"):
                try:
                    # Đọc file BMP
                    header, pixels = read_bmp("temp_upload.bmp")
                    
                    # Giải mã
                    plaintext = decrypt_bytes(pixels, key_input, mode, iv_input if iv_input else None)
                    
                    # Lưu file đã giải mã
                    output_path = "decrypted.bmp"
                    write_bmp(output_path, header, plaintext)
                    
                    # Hiển thị kết quả
                    st.success("Giải mã thành công!")
                    st.image(output_path, caption="Ảnh đã giải mã", use_column_width=True)
                    
                    # Download button
                    with open(output_path, "rb") as file:
                        st.download_button(
                            label="📥 Tải ảnh đã giải mã",
                            data=file,
                            file_name="decrypted.bmp",
                            mime="image/bmp"
                        )
                        
                except Exception as e:
                    st.error(f"Lỗi khi giải mã: {str(e)}")
    
    except Exception as e:
        st.error(f"Lỗi xử lý file: {str(e)}")
    
    finally:
        # Dọn dẹp file tạm
        if os.path.exists("temp_upload.bmp"):
            os.remove("temp_upload.bmp")
else:
    st.info("Vui lòng tải lên file BMP để bắt đầu")

# Thêm footer
st.markdown("---")

st.markdown("Ứng dụng mã hóa BMP bằng AES - Created with Streamlit")
