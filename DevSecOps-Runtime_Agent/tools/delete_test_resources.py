#!/usr/bin/env python3
"""
GuardDuty 테스트 리소스 삭제 스크립트

CloudFormation 스택을 삭제하여 테스트 리소스를 정리합니다.
"""

import boto3
import sys
import os
from botocore.exceptions import ClientError

# Windows에서 UTF-8 인코딩 설정
if sys.platform == "win32":
    import io
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        os.environ['PYTHONIOENCODING'] = 'utf-8'
    except:
        pass

# ANSI 색상 코드
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(text: str):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}{text}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")


def print_success(text: str):
    print(f"{GREEN}✅ {text}{RESET}")


def print_warning(text: str):
    print(f"{YELLOW}⚠️  {text}{RESET}")


def print_info(text: str):
    print(f"{BLUE}ℹ️  {text}{RESET}")


def print_error(text: str):
    print(f"{RED}❌ {text}{RESET}")


def delete_test_resources(stack_name: str = "guardduty-test-resources", region: str = "ap-northeast-2"):
    """CloudFormation 스택 삭제"""
    print_header("GuardDuty 테스트 리소스 삭제")
    
    print_info(f"스택 이름: {stack_name}")
    print_info(f"리전: {region}")
    print()
    
    try:
        cf = boto3.client('cloudformation', region_name=region)
        
        # 스택 존재 확인
        try:
            stack_info = cf.describe_stacks(StackName=stack_name)['Stacks'][0]
            stack_status = stack_info['StackStatus']
            print_info(f"스택 상태: {stack_status}")
        except cf.exceptions.StackNotFoundException:
            print_warning(f"스택 '{stack_name}'을 찾을 수 없습니다.")
            return False
        
        # 스택 삭제
        print_warning("⚠️  모든 테스트 리소스가 삭제됩니다!")
        response = input("정말로 삭제하시겠습니까? (yes/no): ")
        if response.lower() != "yes":
            print_info("취소되었습니다.")
            return False
        
        print_info("스택 삭제 중...")
        cf.delete_stack(StackName=stack_name)
        print_success("스택 삭제 요청 완료")
        
        # 스택 삭제 완료 대기
        print_info("스택 삭제 완료 대기 중... (약 2-3분 소요)")
        waiter = cf.get_waiter('stack_delete_complete')
        waiter.wait(StackName=stack_name)
        
        print_success("스택 삭제 완료!")
        return True
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        print_error(f"CloudFormation 오류 ({error_code}): {error_msg}")
        
        if error_code == 'AccessDeniedException':
            print()
            print_warning("⚠️  IAM 권한이 부족합니다!")
            print()
            print_info("필요한 권한:")
            print("  - cloudformation:DeleteStack")
            print("  - cloudformation:DescribeStacks")
            print()
            print_info("해결 방법:")
            print("  1. IAM 관리자에게 권한 부여 요청")
            print("  2. 또는 PowerUserAccess 정책 부착")
            print()
        
        return False
    except Exception as e:
        print_error(f"오류 발생: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="GuardDuty 테스트 리소스 삭제",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--stack-name",
        default="guardduty-test-resources",
        help="CloudFormation 스택 이름 (기본값: guardduty-test-resources)"
    )
    
    parser.add_argument(
        "--region",
        default="ap-northeast-2",
        help="AWS 리전 (기본값: ap-northeast-2)"
    )
    
    args = parser.parse_args()
    
    delete_test_resources(args.stack_name, args.region)


if __name__ == "__main__":
    main()

