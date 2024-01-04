import hashlib
import requests
import telebot

# Khai báo thông tin API Key
VIRUSTOTAL_API_KEY = '<Input API KEY VT>'
TELEGRAM_BOT_TOKEN = '<Input API Key Bot Telegram>'

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        # Lấy thông tin về tệp đính kèm
        file_info = bot.get_file(message.document.file_id)
        file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}'

        # Tính toán hash của tệp
        with requests.get(file_url) as response:
            file_content = response.content
            file_hash = hashlib.sha256(file_content).hexdigest()

        # Gửi giá trị hash dưới dạng tin nhắn trên Telegram
        bot.send_message(message.chat.id, f"Hash of the file: {file_hash}")

        # Gửi yêu cầu VirusTotal
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        result = response.json()

        # Xử lý kết quả
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            bot.reply_to(message, f"VirusTotal Scan Result: {positives}/{total} positive detections.")
        else:
            bot.reply_to(message, "File not found on VirusTotal.")

    except Exception as e:
        bot.reply_to(message, f"An error occurred: {str(e)}")

@bot.message_handler(content_types=['document'])
def handle_forwarded_document(message):
    # Xử lý tệp được chuyển tiếp
    file_id = message.forward_from_chat.id
    file_info = bot.get_file(file_id)
    file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}'

    with requests.get(file_url) as response:
        file_content = response.content
        file_hash = hashlib.sha256(file_content).hexdigest()

    bot.send_message(message.chat.id, f"Hash of the forwarded file: {file_hash}")

    # Gửi yêu cầu VirusTotal
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    result = response.json()

    # Xử lý kết quả
    if result['response_code'] == 1:
        positives = result['positives']
        total = result['total']
        bot.reply_to(message, f"VirusTotal Scan Result: {positives}/{total} positive detections.")
    else:
        bot.reply_to(message, "File not found on VirusTotal.")

if __name__ == '__main__':
    bot.polling()
