# pip install python-dotenv flask flask-cors flask-mail flask-login flask-mysql-connector itsdangerous

import os, re, inspect
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from flask import Flask, render_template, session, request, jsonify, url_for, redirect
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from werkzeug.security import generate_password_hash, check_password_hash

# 환경 변수 로드
load_dotenv()

# Flask App 생성
app = Flask(__name__)

# 세션 등 데이터 보안을 위한 암호화 키 설정
app.secret_key = os.getenv('SECRET_KEY')

# CORS(Cross-Origin Resource Sharing) 허용할 도메인 설정
CORS(app, resources={r"/*": {"origins": ["http://localhost:5000", "http://127.0.0.1:5000"]}})

# Flask-Mail 설정
app.config.update(
    MAIL_SERVER='smtp.naver.com',   # SMTP 서버 주소
    MAIL_PORT=587,                  # SMTP 포트 번호 (TLS 사용 시 587)
    MAIL_USE_TLS=True,              # TLS 사용 여부
    MAIL_USE_SSL=False,             # SSL 사용 여부 (일반적으로 TLS 사용 시 SSL은 False)
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),       # 이메일 주소 (email-id@domain.com)
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),       # 이메일 비밀번호 (2단계 인증 설정된 계정은 앱 비밀번호)
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME')  # 기본 발신자 이메일 주소
)

mail = Mail(app)
serializer = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

# 이메일 발송
def send_email(to_email, subject, body, template_name, **kwargs):
    msg = Message(f"마이멜로디: {subject}", recipients=[to_email])
    msg.body = body
    msg.html = render_template(template_name, **kwargs)
    mail.send(msg)

# 파일 등록 시 확장자 검증
def allowed_file(filename, allowed_exts={'jpg', 'jpeg', 'png'}):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_exts

# MySQL DB 연결 설정
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),          # DB 서버 주소 (127.0.0.1(로컬 IP)은 테스트 or 동일 서버의 다른 서비스 요청 시 사용)
        user=os.getenv('DB_USER'),          # DB 사용자 이름
        password=os.getenv('DB_PASSWORD'),  # DB 비밀번호
        database=os.getenv('DB_NAME')       # 사용할 DB 이름
    )

# Flask-Login 설정
login_manager = LoginManager()
login_manager.init_app(app)
# 로그인하지 않은 사용자가 보호된 페이지에 접근할 때 이동할 URL
login_manager.login_view = '/login'

class User(UserMixin):
    def __init__(self, id, email, password, nickname, birthdate, email_verified, profile_img, voice, vc_model, current_stage):
        # User 클래스의 생성자. 사용자 정보를 인스턴스 필드로 저장
        self.id = id
        self.email = email
        self.password = password
        self.nickname = nickname
        self.birthdate = birthdate
        self.email_verified = email_verified
        self.profile_img = profile_img
        self.voice = voice
        self.vc_model = vc_model
        self.current_stage = current_stage

    def get_id(self):
        # 이메일을 반환하여 세션에 저장
        return self.email
    
    @staticmethod
    def get_by_email(email):
        # 이메일로 사용자 정보 찾아서 불러오기
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user_data = cursor.fetchone()

        cursor.close()
        db.close()

        if user_data:
            return User(
                id=user_data['id'],
                email=user_data['email'],
                password=user_data['password'],
                nickname=user_data['nickname'],
                birthdate=user_data['birthdate'],
                email_verified=user_data['email_verified'],
                profile_img=user_data['profile_img'],
                voice=user_data['voice'],
                vc_model=user_data['vc_model'],
                current_stage=user_data['current_stage']
            )
        return None

    def check_password(self, password):
        # 비밀번호 검증
        return check_password_hash(self.password, password)

@login_manager.user_loader
def load_user(email):
    # 이메일을 통해 사용자 로드
    return User.get_by_email(email)


@app.context_processor
def calculate_achievement_rate():
    if current_user.is_authenticated:
        current_stage = current_user.current_stage
        last_stage = 21
        achievement_rate = ((current_stage - 1) / last_stage * 100) if last_stage > 0 else 0
        if achievement_rate.is_integer():   # 정수일 때는 정수로 변환
            achievement_rate = int(achievement_rate)
        else:   # 실수일 때는 소수점 첫째 자리까지 반올림하여 변환
            achievement_rate = round(achievement_rate, 1)
    else:   # 로그인하지 않은 경우
        achievement_rate = 0

    return dict(achievement_rate=achievement_rate)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register-profile')
def register_profile():
    email = session.get('email')
    if email is None:
        return render_template('processing-result.html', message="유효하지 않은 세션입니다.", redirect_url=url_for('home'))
    if datetime.now(timezone.utc) > email['expires']:
        session.clear()
        return render_template('processing-result.html', message="세션이 만료되었습니다.", redirect_url=url_for('home'))
    return render_template('register-profile.html')

@app.route('/register-complete')
def register_complete():
    email = session.get('email')
    if email is None:
        return render_template('processing-result.html', message="유효하지 않은 세션입니다.", redirect_url=url_for('home'))
    if datetime.now(timezone.utc) > email['expires']:
        session.clear()
        return render_template('processing-result.html', message="세션이 만료되었습니다.", redirect_url=url_for('home'))
    return render_template('register-complete.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')


@app.route('/main')
@login_required
def main():
    return render_template('mainpage.html', current_stage=current_user.current_stage, profile_img=current_user.profile_img, nickname=current_user.nickname)

@app.route('/quest')
@login_required
def quest():
    email = current_user.email
    stage_id = request.args.get('stage', 1)
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    query = "SELECT current_stage FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    result = cursor.fetchone()
    if int(result['current_stage']) < int(stage_id):
        return render_template('processing-result.html', message="아직 접근할 수 없는 단계입니다.", redirect_url=url_for('main'))

    query = "SELECT * FROM quest_data WHERE stage_id = %s ORDER BY q_number"
    cursor.execute(query, (stage_id,))
    quest_data = cursor.fetchall()
    
    cursor.close()
    db.close()

    if not quest_data:
        return render_template('processing-result.html', message="존재하지 않는 옵션입니다.", redirect_url=url_for('main'))

    for quest in quest_data:
        # q_type이 'Listening' 또는 'Reading'인 경우에만 음성 파일 추가
        if quest['q_type'] in ['Listening', 'Reading']:
            # subquestion을 기반으로 고유한 음성 파일 경로 설정
            quest['audio_file'] = f"/static/gTTS/{re.sub(r'[^a-zA-Z0-9._%+-]', '_', quest['subquestion'])[:50]}.mp3"   # subquestion과 동일한 이름의 파일
        else:
            quest['audio_file'] = None

    return render_template('quest.html', quest_data=quest_data, profile_img=current_user.profile_img, nickname=current_user.nickname)

@app.route('/quest-complete', methods=['PUT'])
@login_required
def quest_complete():
    email = current_user.email
    new_stage_id = int(request.json.get('stage')) + 1

    db = get_db_connection()
    cursor = db.cursor()
    try:
        query = "SELECT current_stage FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        if result is None:
            return jsonify({"success": False, "message": "오류: 사용자 정보를 확인할 수 없습니다."}), 400
        if result[0] < new_stage_id:
            update_query = "UPDATE users SET current_stage = %s WHERE email = %s"
            cursor.execute(update_query, (new_stage_id, email))
            db.commit()
            return jsonify({"success": True, "message": "정보가 갱신되었습니다."}), 200
        
        return jsonify({"success": True, "message": "정보가 갱신되지 않았습니다."}), 200
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/voice')
@login_required
def voice():
    return render_template('voice.html', profile_img=current_user.profile_img, nickname=current_user.nickname)

@app.route('/wordle-index')
@login_required
def wordle_index():
    return render_template('wordle-index.html', profile_img=current_user.profile_img, nickname=current_user.nickname)

@app.route('/wordle')
@login_required
def wordle():
    return render_template('wordle.html', profile_img=current_user.profile_img, nickname=current_user.nickname)

@app.route('/mypage')
@login_required
def mypage():
    return render_template('mypage.html', profile_img=current_user.profile_img, nickname=current_user.nickname, email=current_user.email)

@app.route('/mypage-reset-password')
@login_required
def mypage_reset_password():
    return render_template('mypage-reset-password.html')

@app.route('/unregist')
@login_required
def unregist():
    return render_template('unregist.html')


# 회원 가입 API
@app.route('/user-register', methods=['POST'])
def user_register():
    # 클라이언트가 보낸 JSON 데이터 불러오기
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nickname = data.get('nickname')
    birthdate = data.get('birthdate')

    # 입력 검증
    if not email or not password or not nickname:
        return jsonify({"success": False, "message": "모든 필드는 필수 입력입니다."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "비밀번호는 8자 이상이어야 합니다."}), 400

    # DB 작업을 위해 커서 생성
    db = get_db_connection()
    cursor = db.cursor()
    try:
        # 이메일 중복 확인
        query = "SELECT email FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            return jsonify({"success": False, "message": "이미 사용 중이거나 인증 대기 중인 이메일입니다."}), 400
        
        # 비밀번호 암호화
        hashed_password = generate_password_hash(password)
        
        query = "INSERT INTO users (email, password, nickname, birthdate) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (email, hashed_password, nickname, birthdate))
        db.commit()

        # 토큰 생성
        token = serializer.dumps(email, salt=os.getenv('MAIL_VERIFY_SALT'))
        verify_url = url_for('user_register_verify', token=token, _external=True)
        send_email(
            to_email=email,
            subject="이메일 인증 요청",
            body=f"다음 링크를 통해 이메일을 인증하여 회원 가입을 완료할 수 있습니다: {verify_url}",
            template_name='verification-mail-body.html',
            nickname=nickname,
            verify_url=verify_url
        )
        
        # 세션에 사용자 이메일 저장
        session['email'] = {'email': email, 'expires': datetime.now(timezone.utc) + timedelta(minutes=30)}

        return jsonify({"success": True, "message": "입력하신 메일 주소로 인증 요청이 발송되었습니다.", "redirect_url": url_for('register_profile')})
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# 이미지 파일 저장 위치
IMG_UPLOAD_PATH = 'static/images/profile/'
os.makedirs(IMG_UPLOAD_PATH, exist_ok=True)
app.config['IMG_UPLOAD_PATH'] = IMG_UPLOAD_PATH

# 가입 시 프로필 사진 등록 API
@app.route('/user-register-profile', methods=['POST'])
def user_register_profile():
    email = session.get('email')
    
    # 세션이 유효하지 않은 경우 처리
    if email is None:
        return jsonify({"success": False, "message": "유효하지 않은 세션입니다."}), 403
    if datetime.now(timezone.utc) > email['expires']:
        session.clear()
        return jsonify({"success": False, "message": "세션이 만료되었습니다."}), 403
    
    email = email['email']
    # 파일이 업로드된 경우 처리
    if 'profileImage' in request.files:
        file = request.files['profileImage']

        # 파일 검증
        if not allowed_file(file.filename, allowed_exts={'jpg', 'jpeg', 'png'}):
            return jsonify({"success": False, "message": "지원되지 않는 파일 형식입니다."}), 415
        if file.mimetype not in ['image/jpg', 'image/jpeg', 'image/png']:
            return jsonify({"success": False, "message": "이미지 파일만 허용됩니다."}), 415
        if len(file.read()) > (3 * 1024 * 1024):
            return jsonify({"success": False, "message": "파일 용량은 3MB를 초과할 수 없습니다."}), 413
        file.seek(0)  # 파일 읽기 위치 초기화

        # 안전한 파일명 생성
        safe_email = re.sub(r'[^a-zA-Z0-9._%+-]', '_', email.replace('@', '_at_'))
        filename = f"profile_img_{safe_email}.jpg"

        # 파일 저장
        file.save(os.path.join(app.config['IMG_UPLOAD_PATH'], filename))

        profile_img = filename
    else:
        # 아바타 선택 처리 (클라이언트에서 선택한 아바타 파일명 검증)
        profile_img = request.form.get('profileImage')
        valid_avatars = {'profile_img1.jpg', 'profile_img2.jpg', 'profile_img3.jpg', 'profile_img4.jpg', 'profile_img5.jpg', 'profile_img6.jpg'}
        if profile_img not in valid_avatars:
            return jsonify({"success": False, "message": "유효하지 않은 이미지입니다."}), 400

    db = get_db_connection()
    cursor = db.cursor()
    try:
        query = "UPDATE users SET profile_img = %s WHERE email = %s"
        cursor.execute(query, (profile_img, email))
        db.commit()
        return jsonify({"success": True, "message": "프로필 사진이 등록되었습니다.", "redirect_url": url_for('register_complete')})
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# 이메일 인증 후 회원 가입 완료 API
@app.route('/user-register-verify/<token>', methods=['GET'])
def user_register_verify(token):
    try:
        # 토큰 검증
        email = serializer.loads(token, salt=os.getenv('MAIL_VERIFY_SALT'), max_age=1800)
    except SignatureExpired:
        return render_template('processing-result.html', message="오류: 링크의 유효 시간이 만료되었습니다.")
    except BadTimeSignature:
        return render_template('processing-result.html', message="오류: 잘못된 링크입니다.")

    db = get_db_connection()
    cursor = db.cursor()
    try:
        # 사용자 정보 조회
        query = "SELECT email_verified FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        
        if result is None:
            return render_template('processing-result.html', message="오류: 사용자를 찾을 수 없습니다.")
        if result[0] == 1:
            return render_template('processing-result.html', message="이미 인증된 계정입니다. 로그인 페이지로 이동합니다.", redirect_url=url_for('login'))
        
        update_query = "UPDATE users SET email_verified = TRUE WHERE email = %s"
        cursor.execute(update_query, (email,))
        db.commit()
        return render_template('processing-result.html', message="인증 완료! 로그인 페이지로 이동합니다.", redirect_url=url_for('login'))
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return render_template('processing-result.html', message="오류가 발생했습니다. 관리자에게 문의 바랍니다.")
    except Exception as e:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return render_template('processing-result.html', message="예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다.")
    finally:
        cursor.close()
        db.close()


# 비밀번호 재설정 요청 이메일 발송 API
@app.route('/user-reset-pw-request', methods=['POST'])
def user_reset_pw_request():
    email = request.json.get('email')
    
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    try:
        # 사용자 정보 조회
        query = "SELECT nickname FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"message": "오류: 해당 계정을 찾을 수 없습니다."}), 404
        
        nickname = user['nickname']

        # 토큰 생성
        token = serializer.dumps(email, salt=os.getenv('PW_RESET_SALT'))
        reset_url = url_for('user_reset_pw_verify_template', token=token, _external=True)
        
        # 비밀번호 재설정 이메일 전송
        send_email(
            to_email=email,
            subject="비밀번호 재설정 요청",
            body=f"다음 링크를 통해 비밀번호를 재설정할 수 있습니다: {reset_url}",
            template_name='verification-mail-body.html',
            nickname=nickname,
            verify_url=reset_url
        )
        return jsonify({"message": "비밀번호 재설정 링크가 이메일로 전송되었습니다."}), 200
    except mysql.connector.Error as err:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# 비밀번호 재설정 요청 링크 연결 API
@app.route('/user-reset-pw-verify/<token>', methods=['GET'])
def user_reset_pw_verify_template(token):
    try:
        # 토큰 검증
        serializer.loads(token, salt=os.getenv('PW_RESET_SALT'), max_age=1800)
        return render_template('reset-password.html', token=token, success=True)
    except SignatureExpired:
        return render_template('processing-result.html', message="오류: 링크의 유효 시간이 만료되었습니다.")
    except BadTimeSignature:
        return render_template('processing-result.html', message="오류: 잘못된 링크입니다.")
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return render_template('processing-result.html', message="예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다.")


# 이메일 인증 후 비밀번호 재설정 API
@app.route('/user-reset-pw-verify/<token>', methods=['POST'])
def user_reset_pw_verify(token):
    new_password = request.json.get('newPassword')

    try:
        # 토큰 검증
        email = serializer.loads(token, salt=os.getenv('PW_RESET_SALT'), max_age=1800)
    except SignatureExpired:
        return jsonify({"success": False, "message": "오류: 링크의 유효 시간이 만료되었습니다."}), 500
    except BadTimeSignature:
        return jsonify({"success": False, "message": "오류: 잘못된 링크입니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    
    if len(new_password) < 8:
        return jsonify({"success": False, "message": "비밀번호는 8자 이상이어야 합니다."}), 400

    hashed_password = generate_password_hash(new_password)
    
    db = get_db_connection()
    cursor = db.cursor()
    try:
        # 비밀번호 업데이트
        query = "UPDATE users SET password = %s WHERE email = %s"
        cursor.execute(query, (hashed_password, email))
        db.commit()
        return jsonify({"success": True, "message": "비밀번호가 성공적으로 변경되었습니다.", "redirect_url": url_for('login')}), 200
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# 로그인 API
@app.route('/user-login', methods=['POST'])
def user_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.get_by_email(email)
    if user and user.check_password(password):
        if user.email_verified:
            login_user(user)    # user.get_id()에서 반환된 이메일이 세션에 저장됨
            return jsonify({"success": True, "redirect_url": url_for('main')}), 200
        else:
            return jsonify({"success": False, "message": "이메일 인증이 완료되지 않은 계정입니다."}), 403
    else:
        return jsonify({"success": False, "message": "이메일 또는 비밀번호가 틀렸거나 존재하지 않습니다."}), 401


# 로그아웃 API
@app.route('/user-logout')
@login_required
def user_logout():
    try:
        logout_user()
        return redirect(url_for('login'))
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return render_template('processing-result.html', message="예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다.")


# 회원 정보 수정 API
@app.route('/user-update', methods=['PUT', 'POST'])
@login_required
def user_update():
    email = current_user.email
    # 요청 형식 확인
    if request.is_json:
        data = request.json
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        nickname = data.get('nickname')
        birthdate = data.get('birthdate')
        profile_img = None
    else:
        # form-data 처리
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword')
        nickname = request.form.get('nickname')
        birthdate = request.form.get('birthdate')
        # 파일이 업로드된 경우 처리
        if 'profileImage' in request.files:
            file = request.files['profileImage']

            # 파일 검증
            if not allowed_file(file.filename, allowed_exts={'jpg', 'jpeg', 'png'}):
                return jsonify({"success": False, "message": "지원되지 않는 파일 형식입니다."}), 415
            if file.mimetype not in ['image/jpg', 'image/jpeg', 'image/png']:
                return jsonify({"success": False, "message": "이미지 파일만 허용됩니다."}), 415
            if len(file.read()) > (3 * 1024 * 1024):
                return jsonify({"success": False, "message": "파일 용량은 3MB를 초과할 수 없습니다."}), 413
            file.seek(0)  # 파일 읽기 위치 초기화

            # 안전한 파일명 생성
            safe_email = re.sub(r'[^a-zA-Z0-9._%+-]', '_', email.replace('@', '_at_'))
            filename = f"profile_img_{safe_email}.jpg"

            # 파일 저장
            file.save(os.path.join(app.config['IMG_UPLOAD_PATH'], filename))

            profile_img = filename
        elif request.form.get('profileImage'):
            # 아바타 선택 처리 (클라이언트에서 선택한 아바타 파일명 검증)
            profile_img = request.form.get('profileImage')
            valid_avatars = {'profile_img1.jpg', 'profile_img2.jpg', 'profile_img3.jpg', 'profile_img4.jpg', 'profile_img5.jpg', 'profile_img6.jpg'}
            if profile_img not in valid_avatars:
                return jsonify({"success": False, "message": "유효하지 않은 이미지입니다."}), 400
        else:
            profile_img = None

    if new_password and len(new_password) < 8:
        return jsonify({"success": False, "message": "비밀번호는 8자 이상이어야 합니다."}), 400
    
    db = get_db_connection()
    cursor = db.cursor()

    query = "SELECT password FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"success": False, "message": "오류: 사용자 정보를 확인할 수 없습니다."}), 400
    
    if new_password:
        if check_password_hash(user[0], current_password):
            hashed_password = generate_password_hash(new_password)
        else:
            return jsonify({"success": False, "message": "현재 비밀번호가 올바르지 않습니다."}), 401
    else:
        hashed_password = None
    
    try:
        update_fields = []
        params = []
        if hashed_password:
            update_fields.append('password = %s')
            params.append(hashed_password)
        if nickname:
            update_fields.append('nickname = %s')
            params.append(nickname)
        if birthdate:
            update_fields.append('birthdate = %s')
            params.append(birthdate)
        if profile_img:
            update_fields.append('profile_img = %s')
            params.append(profile_img)
        params.append(email)
        
        if update_fields:
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE email = %s"
            cursor.execute(query, params)
            db.commit()
            return jsonify({"success": True, "message": "입력하신 정보가 정상적으로 반영되었습니다."}), 200
        else:
            return jsonify({"success": False, "message": "수정할 정보가 없습니다."})
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# 회원 탈퇴 API
@app.route('/user-delete', methods=['DELETE'])
@login_required
def user_delete():
    email = current_user.email
    password = request.json.get('password')
    
    db = get_db_connection()
    cursor = db.cursor()
    try:
        # 사용자 정보 조회
        query = "SELECT password FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "message": "오류: 사용자 정보를 확인할 수 없습니다."}), 400

        # 비밀번호가 일치하면 사용자 삭제
        if check_password_hash(user[0], password):
            query = "DELETE FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            db.commit()
            return jsonify({"success": True, "message": "회원 탈퇴가 완료되었습니다.", "redirect_url": url_for('home')}), 200
        else:
            return jsonify({"success": False, "message": "입력하신 비밀번호가 올바르지 않습니다."}), 401
    except mysql.connector.Error as err:
        db.rollback()
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(err)}")
        return jsonify({"success": False, "message": "오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    except Exception as e:
        print(f"{inspect.currentframe().f_code.co_name}에서 오류 발생: {str(e)}")
        return jsonify({"success": False, "message": "예기치 않은 오류가 발생했습니다. 관리자에게 문의 바랍니다."}), 500
    finally:
        cursor.close()
        db.close()


# Flask 실행 (Production 환경에서는 debug=False)
if __name__ == '__main__':
    app.run(port=5000, debug=True)
