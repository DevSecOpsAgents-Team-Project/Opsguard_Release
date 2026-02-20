#!/usr/bin/env python3
"""
GuardDuty 테스트 리소스 배포 스크립트 (CloudFormation)

취약한 EC2 인스턴스, S3 버킷, IAM 사용자를 생성하여 GuardDuty 테스트를 수행할 수 있도록 합니다.
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


def deploy_test_resources(stack_name: str = "guardduty-test-resources", region: str = "ap-northeast-2"):
    """CloudFormation 스택 배포"""
    print_header("GuardDuty 테스트 리소스 배포")
    
    # 프로젝트 루트 경로
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    template_path = os.path.join(project_root, "cloudformation", "test-resources.yaml")
    
    if not os.path.exists(template_path):
        print_error(f"템플릿 파일을 찾을 수 없습니다: {template_path}")
        return False
    
    print_info(f"스택 이름: {stack_name}")
    print_info(f"리전: {region}")
    print_info(f"템플릿: {template_path}")
    print()
    
    try:
        cf = boto3.client('cloudformation', region_name=region)
        
        # 템플릿 파일 읽기
        with open(template_path, 'r', encoding='utf-8') as f:
            template_body = f.read()
        
        # 스택이 이미 존재하는지 확인
        try:
            cf.describe_stacks(StackName=stack_name)
            print_warning(f"스택 '{stack_name}'이 이미 존재합니다.")
            response = input("업데이트하시겠습니까? (yes/no): ")
            if response.lower() != "yes":
                print_info("취소되었습니다.")
                return False
            
            # 스택 업데이트
            print_info("스택 업데이트 중...")
            cf.update_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_NAMED_IAM']
            )
            print_success("스택 업데이트 요청 완료")
            operation = "업데이트"
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in str(e):
                # 스택 생성
                print_info("스택 생성 중...")
                cf.create_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                print_success("스택 생성 요청 완료")
                operation = "생성"
            else:
                raise
        
        # 스택 완료 대기
        print_info(f"스택 {operation} 완료 대기 중... (약 3-5분 소요)")
        try:
            waiter = cf.get_waiter('stack_create_complete' if operation == "생성" else 'stack_update_complete')
            waiter.wait(StackName=stack_name)
            print_success(f"스택 {operation} 완료!")
            print()
        except Exception as waiter_error:
            # 스택 실패 시 상세 오류 정보 출력
            print_error(f"스택 {operation} 실패!")
            print()
            print_header("스택 실패 원인 확인")
            
            try:
                # 스택 이벤트 조회 (최근 50개)
                events = cf.describe_stack_events(StackName=stack_name)
                stack_events = events.get('StackEvents', [])
                
                # 실패한 리소스 찾기
                failed_resources = []
                for event in stack_events:
                    status = event.get('ResourceStatus', '')
                    if 'CREATE_FAILED' in status or 'UPDATE_FAILED' in status:
                        failed_resources.append(event)
                
                if failed_resources:
                    print_error("실패한 리소스 상세 정보:")
                    print()
                    for event in failed_resources:
                        logical_id = event.get('LogicalResourceId', '')
                        resource_type = event.get('ResourceType', '')
                        status = event.get('ResourceStatus', '')
                        reason = event.get('ResourceStatusReason', '')
                        timestamp = event.get('Timestamp', '')
                        
                        print_error(f"❌ {logical_id} ({resource_type})")
                        print(f"   상태: {status}")
                        if reason:
                            print(f"   이유: {reason}")
                        if timestamp:
                            print(f"   시간: {timestamp}")
                        print()
                else:
                    # 실패한 리소스가 명시적으로 없으면 최근 이벤트 표시
                    print_info("최근 스택 이벤트:")
                    for event in stack_events[:15]:
                        status = event.get('ResourceStatus', '')
                        resource_type = event.get('ResourceType', '')
                        logical_id = event.get('LogicalResourceId', '')
                        reason = event.get('ResourceStatusReason', '')
                        
                        if 'FAILED' in status or 'ROLLBACK' in status:
                            print_error(f"  ❌ {logical_id} ({resource_type}): {status}")
                            if reason:
                                print(f"     이유: {reason}")
                        else:
                            print_info(f"  ℹ️  {logical_id} ({resource_type}): {status}")
                
                # 스택 상태 확인
                stack_info = cf.describe_stacks(StackName=stack_name)['Stacks'][0]
                stack_status = stack_info.get('StackStatus', 'UNKNOWN')
                print()
                print_warning(f"스택 상태: {stack_status}")
                
                if stack_status == 'ROLLBACK_COMPLETE':
                    print()
                    print_info("해결 방법:")
                    print("  1. 위의 오류 메시지를 확인하세요")
                    print("  2. 실패한 리소스의 이유를 확인하세요")
                    print("  3. 스택을 삭제한 후 다시 시도하세요:")
                    print(f"     python tools/delete_test_resources.py --stack-name {stack_name}")
                    print("  4. 또는 AWS 콘솔에서 CloudFormation 스택 이벤트를 확인하세요")
                
            except Exception as e:
                print_error(f"스택 정보 조회 실패: {str(e)}")
            
            print()
            raise waiter_error
        
        # 출력 정보 가져오기
        stack_info = cf.describe_stacks(StackName=stack_name)['Stacks'][0]
        outputs = {output['OutputKey']: output['OutputValue'] for output in stack_info.get('Outputs', [])}
        
        print_header("생성된 리소스 정보")
        if 'EC2InstanceId' in outputs:
            print_success(f"EC2 인스턴스 ID: {outputs['EC2InstanceId']}")
            if 'EC2PublicIP' in outputs:
                print_info(f"  공개 IP: {outputs['EC2PublicIP']}")
        
        if 'S3BucketName' in outputs:
            print_success(f"S3 버킷 이름: {outputs['S3BucketName']}")
        
        if 'IAMUserName' in outputs:
            print_success(f"IAM 사용자 이름: {outputs['IAMUserName']}")
        
        if 'SecurityGroupId' in outputs:
            print_info(f"보안 그룹 ID: {outputs['SecurityGroupId']}")
        
        print()
        print_header("위협 시뮬레이션 테스트 명령어")
        if 'EC2InstanceId' in outputs:
            print_info(f"EC2 위협 시뮬레이션:")
            print(f"  python tools/test_threat_simulation.py --scenario ec2_attack --instance-id {outputs['EC2InstanceId']}")
        
        if 'S3BucketName' in outputs:
            print_info(f"S3 위협 시뮬레이션:")
            print(f"  python tools/test_threat_simulation.py --scenario s3_public --bucket-name {outputs['S3BucketName']}")
        
        if 'IAMUserName' in outputs:
            print_info(f"IAM 위협 시뮬레이션:")
            print(f"  python tools/test_threat_simulation.py --scenario iam_abuse --user-name {outputs['IAMUserName']}")
        
        print()
        print_warning("⚠️  테스트 완료 후 리소스를 삭제하세요:")
        print(f"  python tools/delete_test_resources.py --stack-name {stack_name}")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print_error(f"CloudFormation 오류 ({error_code}): {error_msg}")
        
        if error_code == 'AccessDeniedException':
            print()
            print_warning("⚠️  IAM 권한이 부족합니다!")
            print()
            print_info("필요한 권한:")
            print("  - cloudformation:CreateStack")
            print("  - cloudformation:DescribeStacks")
            print("  - cloudformation:UpdateStack")
            print("  - iam:CreateRole, iam:PassRole")
            print("  - ec2:*, s3:*, iam:*")
            print()
            print_info("해결 방법:")
            print("  1. IAM 관리자에게 권한 부여 요청")
            print("  2. 또는 PowerUserAccess 정책 부착")
            print("  3. 상세 권한 목록: docs/REQUIRED_IAM_PERMISSIONS.md 참고")
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
        description="GuardDuty 테스트 리소스 배포",
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
    
    # AWS 자격 증명 확인
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print_success(f"AWS 자격 증명 확인됨")
        print_info(f"Account ID: {identity.get('Account')}")
        print_info(f"User/Role ARN: {identity.get('Arn')}")
    except Exception as e:
        print_error(f"AWS 자격 증명 확인 실패: {str(e)}")
        return
    
    print_warning("⚠️  취약한 리소스가 생성됩니다!")
    print_warning("⚠️  테스트 환경에서만 사용하세요!")
    response = input("계속하시겠습니까? (yes/no): ")
    if response.lower() != "yes":
        print_info("취소되었습니다.")
        return
    
    deploy_test_resources(args.stack_name, args.region)


if __name__ == "__main__":
    main()

