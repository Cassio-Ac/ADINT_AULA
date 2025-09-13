import argparse
import os
from datetime import datetime
import csv
from telethon.sync import TelegramClient
from telethon.tl.types import MessageMediaDocument

# === CONFIG TELEGRAM ===
api_id = 0  # Substitua pelo seu API_ID
api_hash = 'API_HASH'  # Substitua pelo seu API_HASH
phone_number = '+5500000000000'  # Substitua pelo seu número de telefone
target_chat_id = -1001306974125  # Canal Omega Cloud Combos

# === ARQUIVOS LOCAIS ===
CACHE_FILE = 'downloaded_files_cache.txt'
OUTPUT_FOLDER = 'downloads_omega_cloud'
LOG_CSV = 'download_log.csv'

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f)
    return set()

def update_cache(filename):
    with open(CACHE_FILE, 'a', encoding='utf-8') as f:
        f.write(filename + '\n')

def append_csv_log(filename, message_date, status):
    file_exists = os.path.isfile(LOG_CSV)
    with open(LOG_CSV, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(['filename', 'date', 'status'])
        writer.writerow([filename, message_date.strftime('%Y-%m-%d %H:%M:%S'), status])

async def download_files(limit, extension_filter, since_date, dry_run):
    await client.start(phone=phone_number)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    entity = await client.get_entity(target_chat_id)
    print(f'[+] Conectado ao canal: {entity.title}')

    # === MODO DE EXECUÇÃO ===
    mode = []
    if dry_run:
        mode.append('DRY RUN')
    if limit:
        mode.append(f'LIMIT {limit}')
    if extension_filter:
        mode.append(f'EXT {extension_filter}')
    if since_date:
        mode.append(f'SINCE {since_date.strftime("%Y-%m-%d")}')
    if not mode:
        mode_text = 'FULL DOWNLOAD (Sem filtros)'
    else:
        mode_text = ' | '.join(mode)

    print(f'[+] Modo de execução: {mode_text}')

    # === CACHE ===
    cache = load_cache()
    print(f'[+] Arquivos no cache: {len(cache)}')

    downloaded_count = 0
    total_checked = 0
    planned_downloads = 0

    async for message in client.iter_messages(entity, limit=None):
        if not message.media or not isinstance(message.media, MessageMediaDocument):
            continue

        total_checked += 1

        # Mostra progresso a cada 100 mensagens verificadas
        if total_checked % 100 == 0:
            print(f'[→] Mensagens verificadas: {total_checked}...')

        # Filtro por data
        if since_date and message.date < since_date:
            continue

        filename = message.file.name
        if not filename:
            filename = f'message_{message.id}'

        # Filtro por extensão
        if extension_filter and not filename.lower().endswith(extension_filter.lower()):
            continue

        output_path = os.path.join(OUTPUT_FOLDER, filename)

        # Cache para evitar re-download
        if filename in cache or os.path.exists(output_path):
            continue

        if dry_run:
            print(f'[SIMULADO] {filename} | Data: {message.date}')
            append_csv_log(filename, message.date, 'DRY_RUN')
        else:
            try:
                final_path = await message.download_media(file=OUTPUT_FOLDER)
                print(f'[✔] Baixado: {final_path}')
                update_cache(filename)
                append_csv_log(filename, message.date, 'DOWNLOADED')
                downloaded_count += 1
            except Exception as e:
                print(f'[✖] Erro ao baixar {filename}: {e}')
                append_csv_log(filename, message.date, f'ERROR: {e}')

        planned_downloads += 1

        if limit and planned_downloads >= limit:
            print(f'[✓] Limite de {limit} arquivos atingido.')
            break

    print(f'\n[✓] Total mensagens verificadas: {total_checked}')
    print(f'[✓] Arquivos novos baixados: {downloaded_count}')
    print(f'[✓] Arquivos pulados por cache: {len(cache)}')

    if downloaded_count == 0 and not dry_run:
        print('[!] Nenhum arquivo novo foi baixado. Pode ser que tudo já esteja no cache ou os filtros estejam muito restritivos.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Downloader de arquivos do canal Omega Cloud Combos.')
    parser.add_argument('--limit', type=int, default=None, help='Número máximo de arquivos a baixar (exemplo: 10)')
    parser.add_argument('--ext', type=str, default=None, help='Extensão de arquivo para filtrar (ex: .txt ou .zip)')
    parser.add_argument('--since', type=str, default=None, help='Data mínima (YYYY-MM-DD) para baixar arquivos postados depois disso')
    parser.add_argument('--dry-run', action='store_true', help='Simular o download sem salvar nenhum arquivo')

    args = parser.parse_args()

    # Parse de data (se fornecido)
    since_date_obj = None
    if args.since:
        try:
            since_date_obj = datetime.strptime(args.since, '%Y-%m-%d')
        except ValueError:
            print('[✖] Erro: formato da data inválido. Use o formato YYYY-MM-DD.')
            exit(1)

    client = TelegramClient('session_dwldfile', api_id, api_hash)

    with client:
        client.loop.run_until_complete(download_files(args.limit, args.ext, since_date_obj, args.dry_run))
