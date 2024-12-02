# pip install python-dotenv pandas mysql-connector-python

import os
from dotenv import load_dotenv
import pandas as pd
import mysql.connector

# 환경 변수 로드
load_dotenv()

# CSV 파일 불러오기
df = pd.read_csv('quest_data_preprocess.csv', encoding='utf-8')

# NaN 값을 NULL로 변환 (MySQL은 None을 NULL로 처리하므로 NULL이 삽입됨)
df = df.where(pd.notnull(df), None)

# MySQL DB 연결 설정
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),          # DB 서버 주소
        user=os.getenv('DB_USER'),          # DB 사용자 이름
        password=os.getenv('DB_PASSWORD'),  # DB 비밀번호
        database=os.getenv('DB_NAME')       # 사용할 DB 이름
    )

db = get_db_connection()
cursor = db.cursor()
try:
    # 데이터 삽입
    for index, row in df.iterrows():
        query = "INSERT INTO quest_data (stage_id, stage, substage, q_number, q_type, question, subquestion, options_1, options_2, options_3, options_4, options_5, answer, hint) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        values = (row['stage_id'], row['stage'], row['substage'], row['q_number'], row['q_type'], row['question'], row['subquestion'], row['options_1'], row['options_2'], row['options_3'], row['options_4'], row['options_5'], row['answer'], row['hint'])
        cursor.execute(query, values)

    db.commit()
except mysql.connector.Error as err:
    db.rollback()
    print("오류가 발생했습니다: ", err)
finally:
    cursor.close()
    db.close()