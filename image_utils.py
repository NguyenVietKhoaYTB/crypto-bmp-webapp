# image_utils.py
def read_bmp(path):
    with open(path, "rb") as f:
        data = f.read()
    header = data[:54]
    pixels = data[54:]
    return header, pixels

def write_bmp(path, header, pixels_bytes):
    with open(path, "wb") as f:
        f.write(header + pixels_bytes)