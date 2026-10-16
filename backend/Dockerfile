FROM python:3.12-slim
WORKDIR /srv/app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY scenarios /srv/scenarios
ENV SCENARIO_DIR=/srv/scenarios
ENV PYTHONPATH=/srv/app
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
