from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery
from aiogram import F, Router
import app.keyboards as kb
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext
import app.database.requests as rq
from scanner import ScanError, run_nmap, validate_port, validate_target

router = Router()

class ScanIP(StatesGroup):
    ip = State()


class ScanPort(StatesGroup):
    ip = State()
    port = State()


SCAN_NAMES = {
    "fast": "⚡ Быстрое",
    "full": "🔎 Полное",
    "only_ports": "🌐 Топ-порты",
    "info": "📋 Сервисы",
}


async def send_long(message: Message, text: str):
    parts = []
    for start in range(0, len(text), 3900):
        parts.append(text[start:start + 3900])
    for i, part in enumerate(parts):
        if i == len(parts) - 1:
            await message.answer(part, reply_markup=kb.scan_again)
        else:
            await message.answer(part)


@router.message(CommandStart())
async def cmd_start(message: Message):
    await rq.set_user(message.from_user.id)
    await message.answer(
        "TGMAP - Network Scanner\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Привет! Я помогу проверить\n"
        "открытые порты и сервисы.\n\n"
        "Запускайте сканирование только\n"
        "для своих хостов или с разрешения\n"
        "владельца.\n\n"
        "Выберите действие:",
        reply_markup=kb.main,
    )

@router.callback_query(F.data == "about")
async def about(callback: CallbackQuery):
    await callback.answer("")
    await callback.message.edit_text(
        "TGMAP - Network Scanner\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Мини-аналог Nmap в Telegram.\n\n"
        "Возможности:\n"
        "• Проверка открытых портов\n"
        "• Определение сервисов\n"
        "• Считывание баннеров\n"
        "• Сканирование подсетей\n\n"
        "Автор: @Alexey_Navalny2018",
        reply_markup=kb.back,
    )

@router.callback_query(F.data == "scani")
async def scani(callback: CallbackQuery):
    await callback.answer("")
    await callback.message.edit_text(
        "Выберите тип сканирования:\n"
        "━━━━━━━━━━━━━━━━━━━━━━",
        reply_markup=kb.scanip
    )

@router.callback_query(F.data == "fast")
async def fast(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.update_data(scan_type="fast")
    await state.set_state(ScanIP.ip)
    await callback.message.edit_text(
        "⚡ Быстрое сканирование\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Сканирует порты 80, 443.\n"
        "Быстро - ответ за пару секунд.\n\n"
        "Введите IP-адрес или домен:\n\n"
        "Примеры:\n"
        "  8.8.8.8\n"
        "  1.1.1.1\n"
        "  scanme.nmap.org",
        reply_markup=kb.back
    )

@router.callback_query(F.data == "full")
async def full(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.update_data(scan_type="full")
    await state.set_state(ScanIP.ip)
    await callback.message.edit_text(
        "🔎 Полное сканирование\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Сканирует порты 1-1000.\n"
        "Занимает до минуты.\n\n"
        "Введите IP-адрес или домен:\n\n"
        "Примеры:\n"
        "  8.8.8.8\n"
        "  1.1.1.1\n"
        "  scanme.nmap.org",
        reply_markup=kb.back
    )

@router.callback_query(F.data == "only_ports")
async def only_ports(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.update_data(scan_type="only_ports")
    await state.set_state(ScanIP.ip)
    await callback.message.edit_text(
        "🌐 Сканирование топ-портов\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Проверяет 22 популярных порта:\n"
        "SSH, HTTP, MySQL, RDP, Redis...\n\n"
        "Введите IP-адрес или домен:\n\n"
        "Примеры:\n"
        "  8.8.8.8\n"
        "  1.1.1.1\n"
        "  scanme.nmap.org",
        reply_markup=kb.back
    )

@router.callback_query(F.data == "infa")
async def infa(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.update_data(scan_type="info")
    await state.set_state(ScanIP.ip)
    await callback.message.edit_text(
        "📋 Сервисы + баннеры\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Топ-порты + попытка\n"
        "считать баннер сервиса\n"
        "(версия ПО, имя хоста...)\n\n"
        "Введите IP-адрес или домен:\n\n"
        "Примеры:\n"
        "  8.8.8.8\n"
        "  1.1.1.1\n"
        "  scanme.nmap.org",
        reply_markup=kb.back
    )

@router.message(ScanIP.ip)
async def scanip(message: Message, state: FSMContext):
    data = await state.get_data()
    scan_type = data.get("scan_type", "fast")

    try:
        target = validate_target(message.text)
    except ScanError as error:
        await message.answer(f"❌ {error}", reply_markup=kb.back)
        return

    await state.update_data(ip=target)
    await message.answer(
        f"⏳ Сканирование...\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Тип: {SCAN_NAMES.get(scan_type, 'сканирование')}\n"
        f"Цель: {target}"
    )

    try:
        result = await run_nmap(target, scan_type=scan_type)
    except ScanError as error:
        await message.answer(f"❌ Ошибка: {error}", reply_markup=kb.back)
        await state.clear()
        return

    await send_long(message, result.output)
    await state.clear()


# Сканирование порта
@router.callback_query(F.data == "scanp")
async def scanp(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.set_state(ScanPort.ip)
    await callback.message.edit_text(
        "🔍 Сканирование одного порта\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Введите IP-адрес или домен:\n\n"
        "Примеры:\n"
        "  192.168.1.12\n"
        "  scanme.nmap.org",
        reply_markup=kb.back,
    )

@router.message(ScanPort.ip)
async def scan_port_target(message: Message, state: FSMContext):
    try:
        target = validate_target(message.text)
    except ScanError as error:
        await message.answer(f"❌ {error}", reply_markup=kb.back)
        return

    await state.update_data(ip=target)
    await state.set_state(ScanPort.port)
    await message.answer(
        "Введите номер порта (1-65535):\n\n"
        "Пример: 443",
        reply_markup=kb.back
    )

@router.message(ScanPort.port)
async def scan_single_port(message: Message, state: FSMContext):
    try:
        port = validate_port(message.text)
    except ScanError as error:
        await message.answer(f"❌ {error}", reply_markup=kb.back)
        return

    await state.update_data(port=port)
    data = await state.get_data()
    await message.answer(
        f"⏳ Сканирование...\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Цель: {data['ip']}:{port}"
    )

    try:
        result = await run_nmap(data["ip"], port=port)
    except ScanError as error:
        await message.answer(f"❌ Ошибка: {error}", reply_markup=kb.back)
        await state.clear()
        return

    await send_long(message, result.output)
    await state.clear()

# Обработка кнопки назад
@router.callback_query(F.data == "back")
async def back(callback: CallbackQuery, state: FSMContext):
    await callback.answer("")
    await state.clear()
    await callback.message.edit_text(
        "Главное меню\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Выберите действие:",
        reply_markup=kb.main,
    )
