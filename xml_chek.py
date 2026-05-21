from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import xml.etree.ElementTree as ET              # XML
from defusedxml.ElementTree import parse as safe_parse  # XXE
from io import BytesIO
from lxml import etree

import unicodedata                          # нормализует Unicode 
from urllib.parse import unquote            # декодирует URL
import bleach                               # Санитизация XSS
#import re                                  # Валидация
from markupsafe import escape, Markup       # Энкодинг - новая версия

# Диагностика: как проверить работу парсера
def debug_parse_result(result):
    if isinstance(result, str):
        print("Ошибка парсинга:", result)
        return
    print("Парсинг успешен. Структура:")
    print(f"Корень: {result.tag}")
    print(f"Текст корня: {result.text}")
    def print_elements(elem, level=0):
        indent = "  " * level
        text = elem.text.strip() if elem.text else ""
        tail = elem.tail.strip() if elem.tail else ""
        print(f"{indent}Элемент: {elem.tag}, текст: '{text}', хвост: '{tail}'")
        for child in elem:
            print_elements(child, level + 1)
    print_elements(result)

# Уязвимый XML parser
def parse_xml_unsafe(xml_data):
    """УЯЗВИМЫЙ парсер — разрешает XXE"""
    try:
        parser = etree.XMLParser(
            resolve_entities=True,  # Разрешаем external entities
            load_dtd=True,          # Загружаем DTD
            no_network=False        # Разрешаем сетевые обращения
        )
        root = etree.fromstring(xml_data.encode(),parser=parser)
        return root
    except Exception as e:
        return str(e)

# Безопасный XML parser
def parse_xml_safe(xml_data):
    """Защищённый parser — XXE отключён"""
    try:
        parser = etree.XMLParser(
            resolve_entities=False,  # Запрещаем entities
            load_dtd=False,          # Запрещаем DTD
            no_network=True          # Запрещаем сетевые обращения
        )
        root = etree.fromstring(xml_data.encode(),parser=parser)
        return root
    except Exception as e:
        return str(e)
    
'''
# Старая уязвимая функция парсинга XML
def parse_xml_unsafe(xml_data):
    """Уязвимый парсер XML — разрешает внешние сущности"""
    try:
        # Отключаем защиту от XXE — это создаёт уязвимость
        parser = ET.XMLParser()
        parser.parser.StartDocumentHandler = None
        tree = ET.fromstring(xml_data, parser=parser)
        return tree
    except Exception as e:
        return str(e)
'''
'''
# Старая защищённая функция парсинга XML
def parse_xml_safe(xml_data):
    """ Безопасный парсер XML — блокирует внешние сущности и DTD. 
    Использует defusedxml для защиты от XXE и других атак. """
    try:
        # Используем defusedxml — безопасную замену стандартного ET
        tree = safe_parse(BytesIO(xml_data.encode('utf-8')))
        return tree
    except Exception as e:
        return f"Ошибка парсинга XML: {str(e)}"
'''

# Функция полной валидации XML‑файла
def validate_xml_file():
    # 1. Проверяем, что файл загружен
    if 'xmlFile' not in request.files:
        print("Файл не предоставлен", 410)
        return False, None, 'error: 410 — Файл не предоставлен', 410
    file = request.files['xmlFile']
    # 2. Проверяем имя файла
    if file.filename == '':
        print("Имя файла отсутствует", 430)
        return False, None, 'error: 430 — Имя файла отсутствует', 430
    # 3. Проверяем расширение файла
    if not file.filename.lower().endswith('.xml'):
        print("Недопустимый формат файла. Требуется .xml", 440)
        return False, None, 'error: 440 — Требуется файл с расширением .xml', 440
    # 4. Проверяем MIME‑тип файла
    if file.content_type not in ['application/xml', 'text/xml']:
        print(f"Неподдерживаемый тип контента: {file.content_type}", 420)
        return False, None, f'error: 420 — Неподдерживаемый тип файла: {file.content_type}', 420
    # 5. Проверяем размер файла (1 MB)
    max_size = 1024 * 1024  # 1 MB
    file.stream.seek(0, 2)  # Перемещаем указатель в конец
    file_size = file.stream.tell()
    file.stream.seek(0)  # Возвращаем указатель в начало
    if file_size > max_size:
        print("Файл слишком большой. Максимальный размер — 1 MB", 450)
        return False, None, 'error: 450 — Файл слишком большой. Максимальный размер — 1 MB', 450
    # 6. Читаем и декодируем содержимое файла
    try:
        xml_content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        print("Ошибка декодирования файла", 460)
        return False, None, 'error: 460 — Ошибка декодирования файла. Убедитесь, что файл в кодировке UTF‑8', 460
    return True, xml_content, 'Файл прошёл валидацию', 200

'''
def is_safe_svg(svg_content):
    """ Проверяет SVG на наличие потенциально опасных конструкций.
    В реальной реализации используйте специализированные библиотеки. """
    dangerous_patterns = [
        b'<!DOCTYPE',
        b'<!ENTITY',
        b'xlink:href',
        b'javascript:',
        b'data:'
    ]
    for pattern in dangerous_patterns:
        if pattern in svg_content:
            return False
    return True
'''