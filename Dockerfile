FROM python:latest

COPY ./requirements.txt /app/requirements.txt

WORKDIR /app
RUN pip install -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["python", "./run.py"]