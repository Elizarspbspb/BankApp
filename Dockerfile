# Базовый образ с минимальной ОС и Python
FROM python:3.12-slim
# Рабочая директория внутри контейнера
WORKDIR /BankApp
# Копируем файл с зависимостями
COPY requirements.txt .
# Устанавливаем зависимости без использования кэша
RUN pip install --no-cache-dir -r requirements.txt
# Копируем исходный код приложения
COPY . .
# открываем порт (обычно Flask/FastAPI)
EXPOSE 5000
# Запускаем процессы от непривилегированного пользователя
#USER nobody
#USER user
# Команда по умолчанию: запуск приложения
CMD ["python", "app.py"]