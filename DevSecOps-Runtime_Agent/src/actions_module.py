# src/actions_module.py
import logging
import uuid
import json
import boto3
from botocore.exceptions import ClientError
import datetime
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ======================================================
# 공통 응답 스키마 (Helper Function)
# ======================================================
def build_response(action_name, incident_id, status, rollback_data=None, details=None):
    """
    모든 액션의 결과를 표준화된 JSON 형태로 반환합니다.
    """
    return {
        "action_id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "action_name": action_name,
        "status": status,
        "rollback_data": rollback_data or {},
        "details": details or {},
    }

# ======================================================
# 🧠 [고도화 1] 지능형 판단용 함수 (Mock 구현)
# ======================================================

def get_resource_tags(resource_id: str):
    """
    EC2/S3의 태그를 조회하여 LLM 판단에 필요한 컨텍스트를 제공합니다.
    (현재는 Mock 데이터를 반환)
    """
    logger.info(f"[MOCK] 리소스 태그 조회: {resource_id}")
    
    # TODO: 실제 구현 시 boto3.client('resourcegroupstaggingapi').get_resources() 사용
    return {
        "Environment": "Prod",          # 비즈니스 중요도
        "Data_Sensitivity": "PII",      # 데이터 민감도
        "Criticality": "High"
    }

def calculate_risk_score(severity: float, tags: dict, history: dict, costs: dict):
    """
    LLM을 호출하여 최종 위험 점수(Score)와 최적 대응 전략(Strategy)을 계산합니다.
    (현재는 Mock 데이터를 반환)
    """
    logger.info(f"[MOCK] LLM 위험도/비용 분석 요청 (Severity: {severity})")
    
    # TODO: 실제 구현 시 Gemini API 호출 및 프롬프트 엔지니어링 필요
    
    # Mock Logic: 심각도와 환경 태그 기반으로 점수 및 전략 결정
    score = min(severity * 10 + (30 if tags.get("Environment") == "Prod" else 0), 100)
    
    # 기능 2 (비용 효율성) 전략 Mock
    strategy = "ISOLATE"
    if tags.get("Environment") == "Test":
        strategy = "WAF_BLOCK" # 테스트 서버는 격리 대신 저렴한 WAF 차단 선택 가정

    return {
        "score": score,
        "reason": f"심각도 {severity} 및 환경({tags.get('Environment')}) 고려.",
        "optimal_strategy": strategy
    }


# ======================================================
# 🛠️ [NEW] 격리용 보안 그룹 자동 조회/생성 헬퍼 함수
# ======================================================
def _get_or_create_isolation_sg(ec2_client, vpc_id):
    """
    해당 VPC 내에 격리용 보안 그룹이 존재하는지 확인하고,
    없으면 새로 생성하여 ID를 반환합니다.
    """
    group_name = "OpsGuard-Isolation-SG"
    
    try:
        # 1. 이미 존재하는지 검색
        response = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [group_name]},
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )
        
        if response['SecurityGroups']:
            sg_id = response['SecurityGroups'][0]['GroupId']
            logger.info(f"✅ 기존 격리용 보안 그룹 발견: {sg_id} (VPC: {vpc_id})")
            return sg_id
            
        # 2. 없으면 생성
        logger.info(f"✨ 격리용 보안 그룹 생성 중... (VPC: {vpc_id})")
        create_resp = ec2_client.create_security_group(
            GroupName=group_name,
            Description="Created by OpsGuard for Instance Isolation (Deny All)",
            VpcId=vpc_id
        )
        sg_id = create_resp['GroupId']
        
        # 3. 중요: 아웃바운드 규칙 삭제 (생성 시 기본 허용됨 -> 완전 차단 위해 삭제)
        ec2_client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{'IpProtocol': '-1'}] 
        )
        
        # 식별용 태그 부착
        ec2_client.create_tags(
            Resources=[sg_id],
            Tags=[{'Key': 'Name', 'Value': group_name}, {'Key': 'ManagedBy', 'Value': 'OpsGuard'}]
        )
        
        logger.info(f"✅ 격리용 보안 그룹 생성 및 설정 완료: {sg_id}")
        return sg_id

    except ClientError as e:
        logger.error(f"보안 그룹 처리 중 오류: {e}")
        # 오류 발생 시 None 반환하거나 상위로 전파
        raise e

# ======================================================
# 1. EC2 격리 SG로 교체 (자동 생성 로직 적용됨)
# ======================================================
def isolate_instance(instance_id: str, incident_id: str, dry_run=False):
    ec2 = boto3.client("ec2")

    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        if not desc['Reservations']:
             raise ValueError(f"Instance {instance_id} not found")
             
        inst = desc["Reservations"][0]["Instances"][0]
        vpc_id = inst.get('VpcId') # 인스턴스가 속한 VPC ID 확인
        original_sg_ids = [sg["GroupId"] for sg in inst["SecurityGroups"]]

        # ✅ [수정됨] 하드코딩 제거 -> 해당 VPC에 맞는 SG 자동 조회/생성
        if dry_run:
            isolation_sg_id = "sg-dryrun-mock-id"
        else:
            if not vpc_id:
                 raise ValueError("Instance does not belong to a VPC")
            isolation_sg_id = _get_or_create_isolation_sg(ec2, vpc_id)

        if dry_run:
            return build_response(
                "isolate_instance", incident_id, "DRYRUN",
                rollback_data={"instance_id": instance_id,
                            "original_sg_id": original_sg_ids,
                            "new_sg_id": isolation_sg_id}
            )

        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{"Key": "Isolated", "Value": "true"}]
        )

        return build_response(
            "isolate_instance", incident_id, "SUCCESS",
            rollback_data={"instance_id": instance_id,
                        "original_sg_id": original_sg_ids,
                        "new_sg_id": isolation_sg_id},
            details={"message": "Instance isolated successfully"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("isolate_instance", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("isolate_instance", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"isolate_instance 오류: {e}")
        return build_response("isolate_instance", incident_id, "FAILED",
                            details={"error": str(e)})
    except Exception as e:
        logger.error(f"isolate_instance 일반 오류: {e}")
        return build_response("isolate_instance", incident_id, "FAILED",
                            details={"error": str(e)})

# ======================================================
# 2. WAF IPSet에 IP 추가 (실구현)
# ======================================================
def block_ip(source_ip: str, incident_id: str,
            ipset_id="ipset-mock-12345", ipset_name=None, scope="REGIONAL", dry_run=False):

    waf = boto3.client("wafv2", region_name="ap-northeast-2")

    try:
        resp = waf.get_ip_set(
            Name=ipset_name,  # 👈 여기가 없으면 에러남!
            Scope=scope,
            Id=ipset_id
        )
        addresses = resp["IPSet"]["Addresses"]
        lock_token = resp["LockToken"]

        # [수정 1] WAF는 IP 뒤에 /32 (CIDR)가 없으면 에러납니다. 변수로 만들어둡니다.
        ip_cidr = f"{source_ip}/32"

        # [수정 2] 비교할 때도 /32가 붙은 상태로 비교해야 정확합니다.
        if ip_cidr in addresses:
            return build_response(
                "block_ip", incident_id, "SUCCESS",
                # [수정 3] 롤백(unblock)할 때 Name이 필요하니 여기서 저장해야 합니다.
                rollback_data={"ip_address": source_ip,
                               "waf_set_id": ipset_id,
                               "waf_set_name": ipset_name, 
                               "scope": scope},
                details={"message": "Already blocked"}
            )

        if dry_run:
            return build_response(
                "block_ip", incident_id, "DRYRUN",
                rollback_data={"ip_address": source_ip,
                            "waf_set_id": ipset_id,
                            "scope": scope},
            )

        # [수정 4] 리스트에 추가할 때 /32 붙은 값을 넣습니다.
        addresses.append(ip_cidr)

        waf.update_ip_set(
            Name=ipset_name,
            Scope=scope,
            Id=ipset_id,
            Addresses=addresses,
            LockToken=lock_token
        )

        return build_response(
            "block_ip", incident_id, "SUCCESS",
            # [수정 5] 롤백을 위해 waf_set_name 반드시 포함
            rollback_data={"ip_address": source_ip,
                            "waf_set_id": ipset_id,
                            "waf_set_name": ipset_name, 
                            "scope": scope},
            details={"message": "IP blocked"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("block_ip", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("block_ip", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"block_ip 오류: {e}")
        return build_response("block_ip", incident_id, "FAILED",
                            details={"error": str(e)})


# ======================================================
# 3. EC2 스냅샷 생성 (실구현)
# ======================================================
def create_snapshot(instance_id: str, incident_id: str, dry_run=False):
    ec2 = boto3.client("ec2")

    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        inst = desc["Reservations"][0]["Instances"][0]

        root_vol = None
        for m in inst["BlockDeviceMappings"]:
            if m["DeviceName"] == inst["RootDeviceName"]:
                root_vol = m["Ebs"]["VolumeId"]

        if dry_run:
            return build_response(
                "create_snapshot", incident_id, "DRYRUN",
                rollback_data={"volume_id": root_vol},
            )

        snapshot = ec2.create_snapshot(
            VolumeId=root_vol,
            Description=f"Auto snapshot for incident {incident_id}"
        )

        return build_response(
            "create_snapshot", incident_id, "SUCCESS",
            rollback_data={"snapshot_id": snapshot["SnapshotId"],
                        "volume_id": root_vol},
            details={"message": "Snapshot created"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("create_snapshot", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("create_snapshot", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"create_snapshot 오류: {e}")
        return build_response("create_snapshot", incident_id, "FAILED",
                            details={"error": str(e)})


# ======================================================
# EC2-2. 인스턴스 중지 (Mitigation)
# ======================================================
def stop_instance(instance_id: str, incident_id: str, dry_run=False):
    """
    의심스러운 EC2 인스턴스를 중지(stop)합니다.
    """
    ec2 = boto3.client("ec2")

    try:
        # 현재 상태 조회 (롤백/설명용)
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        inst = desc["Reservations"][0]["Instances"][0]
        original_state = inst["State"]["Name"]

        if dry_run:
            return build_response(
                "stop_instance", incident_id, "DRYRUN",
                rollback_data={
                    "instance_id": instance_id,
                    "original_state": original_state,
                },
                details={"message": f"Instance would be stopped from state={original_state}"}
            )

        ec2.stop_instances(InstanceIds=[instance_id])

        return build_response(
            "stop_instance", incident_id, "SUCCESS",
            rollback_data={
                "instance_id": instance_id,
                "original_state": original_state,
            },
            details={"message": "Instance stop initiated"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("stop_instance", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("stop_instance", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"stop_instance 오류: {e}")
        return build_response("stop_instance", incident_id, "FAILED",
                            details={"error": str(e)})


# ======================================================
# EC2-3. 인스턴스 백업 (AMI 생성)
# ======================================================
def backup_instance(instance_id: str, incident_id: str, dry_run=False):
    """
    EC2 인스턴스를 AMI로 백업합니다.
    (Mitigation/Recovery용)
    """
    ec2 = boto3.client("ec2")

    try:
        # AMI 이름 생성
        ami_name = f"opsguard-backup-{incident_id}-{instance_id}"

        if dry_run:
            return build_response(
                "backup_instance", incident_id, "DRYRUN",
                rollback_data={"instance_id": instance_id},
                details={"ami_name": ami_name}
            )

        resp = ec2.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            NoReboot=True,
            Description=f"OpsGuard backup for incident {incident_id}",
        )

        image_id = resp.get("ImageId")

        return build_response(
            "backup_instance", incident_id, "SUCCESS",
            rollback_data={
                "instance_id": instance_id,
                "image_id": image_id,
            },
            details={
                "message": "AMI backup created",
                "ami_name": ami_name,
            }
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("backup_instance", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("backup_instance", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"backup_instance 오류: {e}")
        return build_response("backup_instance", incident_id, "FAILED",
                            details={"error": str(e)})





# ==========================================
# 👤 [시나리오 3] IAM 대응 액션 (실구현)
# ==========================================
def disable_iam_entity(user_name: str, incident_id: str, dry_run: bool = False):
    """
    IAM 사용자에 대해 다음 조치를 취합니다:
    1. 모든 Access Key를 'Inactive'로 변경 (기존 상태 저장)
    2. 'DenyAll' 인라인 정책 부착
    """
    iam = boto3.client("iam") 

    try:
        if dry_run:
            return build_response(
                "disable_iam_entity", incident_id, "DRYRUN",
                rollback_data={"user_name": user_name},
                details={"message": "Would deactivate keys and attach DenyAll policy"}
            )

        # 1. Access Key 목록 조회 및 비활성화
        paginator = iam.get_paginator('list_access_keys')
        deactivated_keys = []
        
        for page in paginator.paginate(UserName=user_name):
            for key in page['AccessKeyMetadata']:
                key_id = key['AccessKeyId']
                status = key['Status']
                
                # 활성 상태인 키만 비활성화하고 기록 (롤백 시 얘네만 켜야 함)
                if status == 'Active':
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=key_id,
                        Status='Inactive'
                    )
                    deactivated_keys.append(key_id)
                    logger.info(f"🚫 Access Key 비활성화됨: {key_id}")

        # 2. DenyAll 인라인 정책 부착
        policy_name = f"OpsGuard-Block-{incident_id}"
        deny_policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        })

        iam.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=deny_policy_doc
        )
        logger.info(f"🚫 DenyAll 정책 부착됨: {policy_name}")

        return build_response(
            "disable_iam_entity", incident_id, "SUCCESS",
            rollback_data={
                "user_name": user_name,
                "policy_name": policy_name,
                "deactivated_keys": deactivated_keys
            },
            details={
                "message": "IAM User blocked successfully",
                "keys_deactivated_count": len(deactivated_keys),
                "policy_attached": policy_name
            }
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchEntity":
            return build_response("disable_iam_entity", incident_id, "FAILED", details={"error": "User Not Found"})
        
        logger.error(f"disable_iam_entity 오류: {e}")
        return build_response("disable_iam_entity", incident_id, "FAILED", details={"error": str(e)})
# ======================================================
# 4. Slack 알림 (Mock 유지)
# ======================================================
def notify_to_slack(message: str, incident_id: str = "UNKNOWN", dry_run: bool = False):
    """
    실제 Slack Webhook 전송 로직 (boto3 대신 requests 사용)
    """
    import requests # 필요한 라이브러리 체크
    
    # 💡 Webhook URL은 환경 변수에서 직접 가져옵니다.
    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if dry_run:
        logger.info(f"[DRY-RUN] Slack 알림 스킵: {message}")
        return build_response("notify_to_slack", incident_id, "SKIPPED", details={"message": message})

    if not slack_webhook_url:
        logger.error("[ACTIONS] SLACK_WEBHOOK_URL 환경 변수가 설정되지 않았습니다.")
        return build_response("notify_to_slack", incident_id, "FAILED", details={"error": "Webhook URL missing"})

    # Slack 메시지 구성 (Rich Format)
    payload = {
        "text": f"🚨 *[Agent B] 보안 대응 알림*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Incident ID", "value": incident_id, "short": True},
                    {"title": "상세 내용", "value": message, "short": False}
                ],
                "footer": "Agent B Runtime Security",
                "ts": int(datetime.datetime.utcnow().timestamp())
            }
        ]
    }

    try:
        response = requests.post(
            slack_webhook_url, 
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        
        logger.info(f"[ACTIONS] Slack 알림 전송 성공: {incident_id}")
        return build_response("notify_to_slack", incident_id, "SUCCESS", details={"message": message})

    except Exception as e:
        logger.error(f"[ACTIONS] Slack 알림 전송 실패: {e}")
        return build_response("notify_to_slack", incident_id, "FAILED", details={"error": str(e)})


# ======================================================
# 5. 인시던트 태그 부착 (조사용) 
# ======================================================
def tag_resource_with_incident(resource_id: str, incident_id: str, resource_type: str = "EC2", dry_run=False):
    """
    조사용으로 인스턴스 등에 Incident 태그를 부착합니다.
    """
    action_name = "tag_resource_with_incident"
    tags_kv = {"IncidentId": incident_id, "Investigation": "true"}
    
    # [안전장치] ID가 없으면 스킵
    if not resource_id or resource_id in ["UNKNOWN-RES", "Unknown-Resource", ""]:
        return build_response(action_name, incident_id, "SKIPPED", details={"reason": "Invalid Resource ID"})

    try:
        # [수정 포인트 1] EC2 판단 로직 강화
        # resource_type이 기본값('EC2')이라도, ID가 'i-'로 시작하지 않으면 EC2가 아님을 인지하도록 조건 수정
        is_ec2_id = resource_id.startswith("i-")
        is_ec2_type = (resource_type == "EC2")

        # 1. EC2: (타입이 EC2이면서 ID도 형식이 맞음) 또는 (그냥 ID가 i-로 시작함)
        if (is_ec2_type and is_ec2_id) or is_ec2_id:
            ec2 = boto3.client("ec2")
            if not dry_run:
                ec2.create_tags(
                    Resources=[resource_id],
                    Tags=[{"Key": k, "Value": v} for k, v in tags_kv.items()]
                )
            detected_type = "EC2"

        # 2. S3: 정확한 타입 매칭
        elif resource_type in ["S3", "S3Bucket"]:
            s3 = boto3.client("s3")
            if not dry_run:
                s3.put_bucket_tagging(
                    Bucket=resource_id,
                    Tagging={'TagSet': [{"Key": k, "Value": v} for k, v in tags_kv.items()]}
                )
            detected_type = "S3"

        # 3. IAM: 유저 타입 매칭
        elif resource_type in ["IAM", "IAMUser", "AccessKey", "User"]:
            iam = boto3.client("iam")
            if not dry_run:
                iam.tag_user(
                    UserName=resource_id,
                    Tags=[{"Key": k, "Value": v} for k, v in tags_kv.items()]
                )
            detected_type = "IAM"
        
        # 4. 아무것도 매칭되지 않은 경우
        else:
            return build_response(
                action_name, incident_id, "SKIPPED",
                details={"reason": f"Unsupported or Mismatched Type: {resource_type} (ID: {resource_id})"}
            )

        return build_response(
                action_name, incident_id, "SUCCESS",
                rollback_data={"resource_id": resource_id, "resource_type": detected_type},
                details={"message": f"Tags attached to {detected_type}"}
            )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("tag_resource_with_incident", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("tag_resource_with_incident", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"tag_resource_with_incident 오류: {e}")
        return build_response("tag_resource_with_incident", incident_id, "FAILED",
                            details={"error": str(e)})
    
    except Exception as e:
        # Boto3 외 일반 에러 처리
        logger.error(f"tag_resource_with_incident 일반 오류: {e}")
        return build_response("tag_resource_with_incident", incident_id, "FAILED",
                            details={"error": str(e)})

# ======================================================
# S3-1. S3 퍼블릭 접근 차단
# ======================================================
def block_s3_public_access(bucket_name: str, incident_id: str, dry_run=False):
    """
    S3 버킷의 퍼블릭 접근을 전역적으로 차단합니다.
    (Account-level이 아니라 bucket-level PublicAccessBlock 기준)
    """
    s3 = boto3.client("s3")

    try:
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }

        if dry_run:
            return build_response(
                "block_s3_public_access", incident_id, "DRYRUN",
                rollback_data={"bucket_name": bucket_name},
                details={"public_access_block": config}
            )

        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=config
        )

        return build_response(
            "block_s3_public_access", incident_id, "SUCCESS",
            rollback_data={"bucket_name": bucket_name},
            details={"message": "S3 public access blocked"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("block_s3_public_access", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("block_s3_public_access", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"block_s3_public_access 오류: {e}")
        return build_response("block_s3_public_access", incident_id, "FAILED",
                            details={"error": str(e)})




# ======================================================
# S3-2. S3 버킷 액세스 로깅 활성화
# ======================================================
def enable_bucket_logging(
    bucket_name: str,
    target_bucket: str,
    target_prefix: str,
    incident_id: str,
    dry_run=False
):
    """
    S3 버킷에 대해 액세스 로그를 남기도록 로깅을 활성화합니다.
    target_bucket: 로그를 저장할 버킷 이름
    target_prefix: 로그 객체 prefix (예: 'access-logs/')
    """
    s3 = boto3.client("s3")

    try:
        if dry_run:
            return build_response(
                "enable_bucket_logging", incident_id, "DRYRUN",
                rollback_data={"bucket_name": bucket_name},
                details={
                    "target_bucket": target_bucket,
                    "target_prefix": target_prefix
                }
            )

        s3.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": target_prefix
                }
            }
        )

        return build_response(
            "enable_bucket_logging", incident_id, "SUCCESS",
            rollback_data={"bucket_name": bucket_name},
            details={
                "message": "Bucket logging enabled",
                "target_bucket": target_bucket,
                "target_prefix": target_prefix
            }
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("enable_bucket_logging", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("enable_bucket_logging", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"enable_bucket_logging 오류: {e}")
        return build_response("enable_bucket_logging", incident_id, "FAILED",
                            details={"error": str(e)})





# ======================================================
# IAM-1. 액세스 키 비활성화
# ======================================================
def disable_access_key(user_name: str, access_key_id: str, incident_id: str, dry_run=False):
    """
    특정 IAM User의 Access Key를 Inactive로 비활성화합니다.
    """
    iam = boto3.client("iam")

    try:
        if dry_run:
            return build_response(
                "disable_access_key", incident_id, "DRYRUN",
                rollback_data={"user_name": user_name, "access_key_id": access_key_id}
            )

        iam.update_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status="Inactive"
        )

        return build_response(
            "disable_access_key", incident_id, "SUCCESS",
            rollback_data={"user_name": user_name, "access_key_id": access_key_id},
            details={"message": "Access key disabled"}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("disable_access_key", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("disable_access_key", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"disable_access_key 오류: {e}")
        return build_response("disable_access_key", incident_id, "FAILED",
                            details={"error": str(e)})




# ======================================================
# IAM-2. 관리자 권한 정책 Detach
# ======================================================
def detach_admin_policies(user_name: str, incident_id: str, dry_run=False):
    """
    주어진 IAM User에 붙어있는 관리자 권한 정책(예: AdministratorAccess)을 Detach합니다.
    (간단하게: 모든 attached managed policy를 떼는 방식으로 구현 가능)
    """
    iam = boto3.client("iam")

    try:
        attached = iam.list_attached_user_policies(UserName=user_name)
        policies = attached.get("AttachedPolicies", [])
        policy_arns = [p["PolicyArn"] for p in policies]

        if dry_run:
            return build_response(
                "detach_admin_policies", incident_id, "DRYRUN",
                rollback_data={"user_name": user_name, "policy_arns": policy_arns},
                details={"detached_policies": policy_arns}
            )

        # 실제 detach 수행
        for arn in policy_arns:
            iam.detach_user_policy(
                UserName=user_name,
                PolicyArn=arn
            )

        return build_response(
            "detach_admin_policies", incident_id, "SUCCESS",
            rollback_data={"user_name": user_name, "policy_arns": policy_arns},
            details={"message": "All attached managed policies detached", "count": len(policy_arns)}
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("detach_admin_policies", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("detach_admin_policies", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"detach_admin_policies 오류: {e}")
        return build_response("detach_admin_policies", incident_id, "FAILED",
                            details={"error": str(e)})


# ======================================================
# NET-1. VPC Flow Logs 활성화 (조사/포렌식)
# ======================================================
def enable_vpc_flow_logs(
    vpc_id: str,
    incident_id: str,
    log_group_name: str,
    iam_role_arn: str,
    dry_run: bool = False,
):
    """
    지정된 VPC에 대해 VPC Flow Logs를 활성화합니다.
    로그는 CloudWatch Logs로 전송한다고 가정합니다.
    """
    ec2 = boto3.client("ec2")

    try:
        if dry_run:
            return build_response(
                "enable_vpc_flow_logs", incident_id, "DRYRUN",
                rollback_data={"vpc_id": vpc_id},
                details={
                    "log_group_name": log_group_name,
                    "iam_role_arn": iam_role_arn,
                }
            )

        # API 호출
        resp = ec2.create_flow_logs(
            ResourceType="VPC",
            ResourceIds=[vpc_id],
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=iam_role_arn,
        )

        # 🛑 [중요 수정] 부분 실패(Unsuccessful) 체크 로직 추가
        # API가 에러를 뱉지 않고 'Unsuccessful' 리스트에 에러를 담아주는 경우를 잡아야 함
        if resp.get("Unsuccessful"):
            # 실패 사유 첫 번째를 가져옴
            error_msg = resp["Unsuccessful"][0]["Error"]["Message"]
            logger.error(f"VPC Flow Log 생성 실패 (API 응답): {error_msg}")
            
            return build_response(
                "enable_vpc_flow_logs", incident_id, "FAILED",
                details={"error": f"AWS API Error: {error_msg}"}
            )

        # 정상적으로 ID를 가져왔는지 확인
        flow_log_ids = resp.get("FlowLogIds", [])
        
        if not flow_log_ids:
            # 성공했다고 했는데 ID가 없는 경우 (매우 드묾)
            return build_response(
                "enable_vpc_flow_logs", incident_id, "FAILED",
                details={"error": "No FlowLogIds returned from AWS"}
            )

        # 성공 리턴
        return build_response(
            "enable_vpc_flow_logs", incident_id, "SUCCESS",
            rollback_data={
                "vpc_id": vpc_id,
                "flow_log_ids": flow_log_ids, # 이제 여기에 값이 확실히 들어갑니다
            },
            details={
                "message": "VPC Flow Logs enabled",
                "log_group_name": log_group_name,
                "iam_role_arn": iam_role_arn,
                "created_ids": flow_log_ids
            }
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("enable_vpc_flow_logs", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("enable_vpc_flow_logs", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"enable_vpc_flow_logs 오류: {e}")
        return build_response("enable_vpc_flow_logs", incident_id, "FAILED",
                            details={"error": str(e)})
    
# ======================================================
# LOG-1. CloudTrail 이벤트 조회 (조사용)
# ======================================================
def lookup_cloudtrail_events(
    user_name: str,
    incident_id: str,
    lookback_hours: int = 1,
    dry_run: bool = False,
):
    """
    특정 IAM User에 대해 최근 CloudTrail 이벤트를 조회합니다.
    (포렌식/조사용, 롤백은 필요 없음)
    """
    cloudtrail = boto3.client("cloudtrail")

    # 조회 기간 계산
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(hours=lookback_hours)

    if dry_run:
        return build_response(
            "lookup_cloudtrail_events", incident_id, "DRYRUN",
            rollback_data={},
            details={
                "user_name": user_name,
                "lookback_hours": lookback_hours,
            }
        )

    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[{
                "AttributeKey": "Username",
                "AttributeValue": user_name,
            }],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=20,
        )

        events = resp.get("Events", [])

        # 너무 많은 정보 말고, 핵심 필드만 요약해서 details에 담기
        simplified = []
        for ev in events[:10]:
            simplified.append({
                "EventId": ev.get("EventId"),
                "EventName": ev.get("EventName"),
                "EventTime": ev.get("EventTime").isoformat() if ev.get("EventTime") else None,
                "Resources": [
                    r.get("ResourceName") for r in ev.get("Resources", [])
                ],
            })

        return build_response(
            "lookup_cloudtrail_events", incident_id, "SUCCESS",
            rollback_data={},
            details={
                "user_name": user_name,
                "lookback_hours": lookback_hours,
                "event_count": len(events),
                "events": simplified,
            }
        )

    except ClientError as e:
        code = e.response["Error"]["Code"]

        if code == "AccessDenied":
            return build_response("lookup_cloudtrail_events", incident_id, "FAILED",
                                details={"error": "AccessDenied"})

        if code in ("Throttling", "RequestLimitExceeded"):
            return build_response("lookup_cloudtrail_events", incident_id, "RETRY",
                                details={"error": code})

        logger.error(f"lookup_cloudtrail_events 오류: {e}")
        return build_response("lookup_cloudtrail_events", incident_id, "FAILED",
                            details={"error": str(e)})


def enable_s3_bucket_logging(bucket_name: str, target_bucket: str, incident_id: str, dry_run: bool = False):
    """
    S3 버킷의 서버 액세스 로깅을 활성화합니다.
    (대상 버킷이 없으면 자동으로 생성합니다)
    """
    if dry_run:
        logger.info(f"[DRY-RUN] S3 로깅 활성화 스킵: {bucket_name}")
        # build_response 함수가 없다면 mock으로 처리하거나 기존 코드 사용
        return {"status": "SKIPPED", "action": "enable_s3_bucket_logging"}

    try:
        s3_client = boto3.client('s3')
        
        # ========================================================
        # [추가됨] 대상 버킷(Target Bucket) 존재 확인 및 생성 로직
        # ========================================================
        try:
            s3_client.head_bucket(Bucket=target_bucket)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # 404: 버킷이 없으면 생성
            if error_code == '404':
                logger.info(f"[ACTIONS] 대상 버킷({target_bucket})이 없어 생성합니다.")
                s3_client.create_bucket(
                    Bucket=target_bucket,
                    # 서울 리전(ap-northeast-2) 기준 설정. 리전이 다르면 수정 필요.
                    CreateBucketConfiguration={'LocationConstraint': 'ap-northeast-2'}
                )
                
                # (권장) 로그 버킷의 퍼블릭 액세스 차단 (보안 강화)
                s3_client.put_public_access_block(
                    Bucket=target_bucket,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
                    }
                )
            else:
                # 403 등 다른 에러면 상위 catch로 던짐
                raise e
        # ========================================================

        # 로그가 저장될 위치 설정 (target_bucket/logs/bucket_name/ 형식)
        logging_config = {
            'LoggingEnabled': {
                'TargetBucket': target_bucket,
                'TargetPrefix': f"logs/{bucket_name}/"
            }
        }
        
        s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus=logging_config
        )
        
        logger.info(f"[ACTIONS] S3 로깅 활성화 성공: {bucket_name}")
        # build_response 함수가 있는 기존 환경에 맞게 반환
        return build_response("enable_s3_bucket_logging", incident_id, "SUCCESS")

    except Exception as e:
        logger.error(f"[ACTIONS] S3 로깅 활성화 실패: {e}")
        return build_response("enable_s3_bucket_logging", incident_id, "FAILED", details={"error": str(e)})


# ======================================================
# Actions Wrapper Class — 모든 함수를 묶어주는 역할
# ======================================================
class Actions:
    def __init__(self, dry_run: bool = False):
        """
        Actions 클래스 초기화
        
        Args:
            dry_run: True이면 모든 액션을 dry-run 모드로 실행 (실제 변경 없음)
        """
        self.dry_run = dry_run
    
    # --- Action Execution Functions ---
    def isolate_instance(self, instance_id: str, incident_id: str):
        return isolate_instance(instance_id, incident_id, dry_run=self.dry_run)

    def block_ip(self, source_ip: str, incident_id: str):
        return block_ip(source_ip, incident_id)

    def create_snapshot(self, instance_id: str, incident_id: str):
        return create_snapshot(instance_id, incident_id, dry_run=self.dry_run)
    
    def disable_iam_entity(self, user_name: str, incident_id: str):
        return disable_iam_entity(user_name, incident_id)
    
    def tag_resource_with_incident(self, resource_id: str, incident_id: str, resource_type: str):
        return tag_resource_with_incident(resource_id, incident_id, resource_type, dry_run=self.dry_run)

    # --- NEW: S3 / IAM 전용 액션들 ---
    def block_s3_public_access(self, bucket_name: str, incident_id: str):
        return block_s3_public_access(bucket_name, incident_id, dry_run=self.dry_run)

    def enable_bucket_logging(self, bucket_name: str, target_bucket: str, target_prefix: str, incident_id: str):
        return enable_bucket_logging(bucket_name, target_bucket, target_prefix, incident_id)

    def disable_access_key(self, user_name: str, access_key_id: str, incident_id: str):
        return disable_access_key(user_name, access_key_id, incident_id, dry_run=self.dry_run)

    def detach_admin_policies(self, user_name: str, incident_id: str):
        return detach_admin_policies(user_name, incident_id, dry_run=self.dry_run)
    
    
    # --- NEW: EC2 / NET / LOG 고도화 액션들 ---
    def stop_instance(self, instance_id: str, incident_id: str):
        return stop_instance(instance_id, incident_id, dry_run=self.dry_run)

    def enable_vpc_flow_logs(self, vpc_id: str, incident_id: str, log_group_name: str, iam_role_arn: str):
        return enable_vpc_flow_logs(vpc_id, incident_id, log_group_name, iam_role_arn)

    def lookup_cloudtrail_events(self, user_name: str, incident_id: str, lookback_hours: int = 1):
        return lookup_cloudtrail_events(user_name, incident_id, lookback_hours, dry_run=self.dry_run)

    def backup_instance(self, instance_id: str, incident_id: str):
        return backup_instance(instance_id, incident_id, dry_run=self.dry_run)


    # --- Notification ---
    def notify_to_slack(self, message: str, incident_id: str):
        return notify_to_slack(message, incident_id, dry_run=self.dry_run)

    # --- [New] Decision Support Functions ---
    def get_resource_tags(self, resource_id: str):
        return get_resource_tags(resource_id)

    def calculate_risk_score(self, severity: float, tags: dict, history: dict, costs: dict):
        return calculate_risk_score(severity, tags, history, costs)

    def enable_s3_bucket_logging(self, bucket_name: str, target_bucket: str, incident_id: str):
        return enable_s3_bucket_logging(bucket_name, target_bucket, incident_id, dry_run=self.dry_run)
