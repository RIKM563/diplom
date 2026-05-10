# Запуск проекта в VS Code

1. Открыть папку проекта:

   `C:\Users\artem\PycharmProjects\risk_system`

2. Убедиться, что выбран интерпретатор:

   `.venv\Scripts\python.exe`

3. Запустить сервер одним из способов:

   - `Terminal -> Run Task -> Run FastAPI server`;
   - `Run and Debug -> FastAPI: risk_system`.

4. Открыть UI:

   `http://127.0.0.1:8000`

5. Основной endpoint для демонстрации:

   `POST /pipeline/full`

Если VS Code показывает русские файлы некорректно, нужно проверить в правом нижнем углу кодировку файла и выбрать UTF-8.
