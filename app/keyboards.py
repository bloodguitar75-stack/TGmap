from aiogram.types import (ReplyKeyboardMarkup, KeyboardButton, 
                           InlineKeyboardButton, InlineKeyboardMarkup)


main = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text="⚡ Сканировать IP", callback_data="scani")],
    [InlineKeyboardButton(text="🔍 Сканировать порт", callback_data="scanp")], 
    [InlineKeyboardButton(text="ℹ️ О боте", callback_data="about")]
])                    

scanip = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text="⚡ Быстрое (80, 443)", callback_data="fast")],
    [InlineKeyboardButton(text="🔎 Полное (1-1000)", callback_data="full")], 
    [InlineKeyboardButton(text="🌐 Топ-порты (22 шт)", callback_data="only_ports")],
    [InlineKeyboardButton(text="📋 Сервисы + баннеры", callback_data="infa")], 
])

back = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text="🔙 Назад в меню", callback_data="back")]
])

scan_again = InlineKeyboardMarkup(inline_keyboard=[
    [InlineKeyboardButton(text="🔄 Сканировать ещё", callback_data="scani")],
    [InlineKeyboardButton(text="🔙 Назад в меню", callback_data="back")]
])
