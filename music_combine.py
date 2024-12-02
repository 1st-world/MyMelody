# pip install pydub

from pydub import AudioSegment

def normalize_ext(ext):
    ext = ext.lower()
    if not ext.startswith('.'):
        return '.' + ext
    return ext

def ensure_ext(filename, ext):
    if not filename.endswith(ext):
        filename += ext
    return filename

def combine(vocal_file, inst_file, ext='.mp3', exp_filename=None):
    ext = normalize_ext(ext)

    # 확장자 유효성 검사
    valid_exts = ['.mp3', '.wav', '.ogg', '.flv', '.aac', '.m4a', '.wma', '.avi', '.mp4']
    if ext not in valid_exts:
        raise ValueError(f"Invalid extension: {ext}. Supported extensions are: {valid_exts}")
    
    try:
        # 오디오 파일 불러오기
        audio1 = AudioSegment.from_file(vocal_file)
        audio2 = AudioSegment.from_file(inst_file)

        # 두 오디오 트랙을 겹쳐서 결합
        combined = audio1.overlay(audio2)

        if exp_filename:
            exp_filename = ensure_ext(exp_filename, ext)
            output_filename = exp_filename
        else:
            output_filename = ensure_ext(f"{vocal_file}_combined", ext)

        # 결합된 파일 저장
        combined.export(output_filename, format=ext.strip('.'))
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    combine(
        vocal_file="Giveon - Heartbreak Anniversary (Inst. only).mp3",
        inst_file="Giveon - Heartbreak Anniversary (10000).mp3",
        ext='.mp3'
    )