#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
인코딩 문제 수정 스크립트
UTF-16 LE로 저장된 파일을 UTF-8로 변환합니다.
"""

import sys
import os

def convert_file_to_utf8(filepath):
    """파일을 UTF-16 LE에서 UTF-8로 변환"""
    try:
        # UTF-16 LE로 읽기
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # BOM 제거 (FF FE)
        if data.startswith(b'\xff\xfe'):
            data = data[2:]
        
        # UTF-16 LE 디코딩
        content = data.decode('utf-16-le')
        
        # UTF-8로 저장
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ {filepath} 변환 완료")
        return True
    except Exception as e:
        print(f"❌ {filepath} 변환 실패: {e}")
        return False

if __name__ == "__main__":
    files_to_convert = [
        'test_severity_decision.py',
        'xai_explainer.py'
    ]
    
    for filepath in files_to_convert:
        if os.path.exists(filepath):
            convert_file_to_utf8(filepath)
        else:
            print(f"⚠️ {filepath} 파일을 찾을 수 없습니다.")

