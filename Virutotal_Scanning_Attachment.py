import hashlib
import requests
import telebot

# Khai báo thông tin API Key
VIRUSTOTAL_API_KEY = '<Input API KEY VT>'
TELEGRAM_BOT_TOKEN = '<Input API Key Bot Telegram>'

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

def get_file_hash(file_content):
    # Tính toán hash của tệp
    file_hash = hashlib.sha256(file_content).hexdigest()
    return file_hash

@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        # Lấy thông tin về tệp đính kèm
        file_info = bot.get_file(message.document.file_id)
        file_url = f'https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}'

        # Tải nội dung tệp
        with requests.get(file_url) as response:
            file_content = response.content
            file_hash = get_file_hash(file_content)

        # Gửi giá trị hash
        bot.send_message(message.chat.id, f"Hash of the file: {file_hash}")

        # Gửi yêu cầu VirusTotal
        vt_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        vt_response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=vt_params)
        vt_result = vt_response.json()

        # Xử lý kết quả VirusTotal
        if vt_result['response_code'] == 1:
            positives = vt_result['positives']
            total = vt_result['total']
            vt_report_url = vt_result['permalink']

            message_text = (
                f"VirusTotal Scan Result: {positives}/{total} positive detections.\n"
                f"See the detailed report: {vt_report_url}"
            )
            bot.reply_to(message, message_text)
        else:
            bot.reply_to(message, "File not found on VirusTotal.")

    except Exception as e:
        bot.reply_to(message, f"An error occurred: {str(e)}")

@bot.message_handler(content_types=['text'])
def handle_text(message):
    # Xử lý khi người dùng gửi một URL
    if message.entities:
        for entity in message.entities:
            if entity.type == 'url':
                url = message.text[entity.offset:entity.offset + entity.length]
                scan_url(message.chat.id, url)

def scan_url(chat_id, url):
    try:
        # Gửi yêu cầu VirusTotal cho URL
        vt_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
        vt_response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=vt_params)
        vt_result = vt_response.json()

        # Xử lý kết quả VirusTotal
        if vt_result['response_code'] == 1:
            positives = vt_result['positives']
            total = vt_result['total']
            vt_report_url = vt_result['permalink']

            message_text = (
                f"VirusTotal Scan Result for {url}: {positives}/{total} positive detections.\n"
                f"See the detailed report: {vt_report_url}"
            )
            bot.send_message(chat_id, message_text)
        else:
            bot.send_message(chat_id, f"URL not found on VirusTotal.")

    except Exception as e:
        bot.send_message(chat_id, f"An error occurred: {str(e)}")

if __name__ == '__main__':
    bot.polling()
