# pip install gtts playsound==1.2.2 flask-mysql-connector

import os, re
from gtts import gTTS
import playsound as ps
import mysql.connector

def speak(script):
    tts = gTTS(text=script, lang='en')
    tts.save('filename.mp3')
    ps.playsound('filename.mp3')

def make_tts_file(script):
	# 파일명을 안전하게 만들기 위해 정규표현식 사용
    safe_script = re.sub(r'[^a-zA-Z0-9._%+-]', '_', script)[:50]  # 50자 이하로 제한
    filename = f"{safe_script}.mp3"
    
    tts = gTTS(text=script, lang='en')
    tts.save(filename)

# MySQL DB 연결 설정
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),          # DB 서버 주소 (127.0.0.1은 현재 로컬 IP. 테스트용 or 동일 서버의 다른 서비스 요청 시 사용)
        user=os.getenv('DB_USER'),          # DB 사용자 이름
        password=os.getenv('DB_PASSWORD'),  # DB 비밀번호
        database=os.getenv('DB_NAME')       # 사용할 DB 이름
    )

def fetch_and_speak_subquestions():
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # 쿼리 실행: q_type이 'Listening' 또는 'Reading'인 경우에 대한 서브질문 조회
        query = "SELECT subquestion FROM quest_data WHERE q_type IN ('Listening', 'Reading')"
        cursor.execute(query)
        
        # 결과 가져오기
        results = cursor.fetchall()
        
        for row in results:
            subquestion = row[0]
            make_tts_file(subquestion)  # 각 서브질문에 대해 TTS 실행
    except mysql.connector.Error as err:
        print(f"DB 오류 발생: {err}")
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

# 함수 호출
fetch_and_speak_subquestions()