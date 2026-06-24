import json
import re


def extract_firebase_config(text):
    # Khởi tạo một dictionary để lưu kết quả
    config_dict = {}

    # Sử dụng Regex để tìm các cặp key: "value" hoặc key: 'value'
    # Pattern này bắt được cả dấu nháy đơn và nháy kép
    pattern = r"(\w+)\s*:\s*[\"']([^\"']+)[\"']"

    matches = re.findall(pattern, text)

    for key, value in matches:
        config_dict[key] = value

    return config_dict


# Đoạn text chứa config của bạn
raw_text = """
const firebaseConfig = {
    apiKey: "AIzaSyCbk1_oS6CM71v2z5tgxQPk2uY7xKHLNmw",
    authDomain: "taxiappd.firebaseapp.com",
    databaseURL: "https://taxiappd.firebaseio.com",
    projectId: "taxiappd",
    storageBucket: "taxiappd.firebasestorage.app",
    messagingSenderId: "778491647756",
    appId: "1:778491647756:web:b5544ef6bb0beea61fdb29",
    measurementId: "G-TMTDGJ63W4"
}
"""

# Chạy thử tool
result = extract_firebase_config(raw_text)

if result:
    print("--- Kết quả đọc cấu hình Firebase ---")
    # In ra dạng JSON cho đẹp mắt và dễ đọc
    print(json.dumps(result, indent=4))

    # Bạn có thể truy cập từng phần tử như thế này:
    # print(f"API Key của bạn là: {result.get('apiKey')}")
else:
    print("Không tìm thấy cấu hình Firebase hợp lệ trong đoạn text.")