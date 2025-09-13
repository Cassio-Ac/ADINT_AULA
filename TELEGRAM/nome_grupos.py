from telethon.sync import TelegramClient

api_id = 29746479
api_hash = 'e9c6d52ad31d7233a2f9f323d5d0f500'
phone_number = '+5551981184847'  # Seu número do Telegram

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
