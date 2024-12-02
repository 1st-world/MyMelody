CREATE DATABASE mymelody DEFAULT CHARACTER SET utf8mb4;
USE mymelody;

CREATE TABLE users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    nickname VARCHAR(50) NOT NULL,
    birthdate DATE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    profile_img VARCHAR(255) DEFAULT 'profile_img1.jpg',
    voice VARCHAR(255),
    vc_model VARCHAR(255),
    current_stage SMALLINT NOT NULL DEFAULT 1
);

UPDATE users SET nickname = '관리자', email_verified = TRUE, current_stage = 22 WHERE email = 'no-reply-mymelody@naver.com';

SELECT * FROM users;

-- 이벤트 스케줄러 활성화
SET GLOBAL event_scheduler = ON;

CREATE EVENT delete_unverified_users
ON SCHEDULE EVERY 1 MINUTE
DO
    DELETE FROM users
    WHERE email_verified = FALSE
    AND created_at < NOW() - INTERVAL 30 MINUTE;

SHOW EVENTS;

CREATE TABLE quest_data (
	stage_id SMALLINT,
    stage VARCHAR(10),
    substage VARCHAR(10),
    q_number TINYINT,
    q_type VARCHAR(50),
    question VARCHAR(100),
    subquestion VARCHAR(255),
    options_1 VARCHAR(100),
    options_2 VARCHAR(100),
    options_3 VARCHAR(100),
    options_4 VARCHAR(100),
    options_5 VARCHAR(100),
    answer VARCHAR(255),
    hint VARCHAR(255),
    PRIMARY KEY (stage, substage, q_number)
);

SELECT * FROM quest_data;