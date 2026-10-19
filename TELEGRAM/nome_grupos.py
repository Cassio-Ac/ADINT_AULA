import os
from telethon.sync import TelegramClient

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

api_id = int(os.environ.get('TELEGRAM_API_ID', '0'))
api_hash = os.environ.get('TELEGRAM_API_HASH', '')
phone_number = os.environ.get('TELEGRAM_PHONE', '')

output_file = 'lista_chats.txt'

client = TelegramClient('session_dwldfile', api_id, api_hash)

async def listar_chats():
    await client.start(phone=phone_number)

    with open(output_file, 'w', encoding='utf-8') as f:
        async for dialog in client.iter_dialogs():
            linha = f"Nome: {dialog.name} | ID: {dialog.id} | Tipo: {type(dialog.entity)}\n"
            print(linha.strip())
            f.write(linha)

    print(f'\n[✓] Lista de chats salva em: {output_file}')

with client:
    client.loop.run_until_complete(listar_chats())
