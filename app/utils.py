import requests
import json # 需要导入 json 来序列化请求体
import os # os 仍可能被其他地方使用，暂时保留
import logging

# 获取 logger 实例
logger = logging.getLogger(__name__)

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"

def verify_api_token(token_string):
    """
    使用 Cloudflare API /user/tokens/verify 端点验证 Token 的有效性。

    Args:
        token_string: 要验证的 Cloudflare API Token。

    Returns:
        bool: 如果 Token 有效则返回 True，否则返回 False。
              如果 API 请求失败或出现其他错误，也可能返回 False 或抛出异常。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    verify_url = f"{CLOUDFLARE_API_BASE_URL}/user/tokens/verify"

    try:
        response = requests.get(verify_url, headers=headers, timeout=10) # 设置 10 秒超时

        if response.status_code == 200:
            json_response = response.json()
            # 检查响应结构和 success 字段
            if json_response.get("success") is True and json_response.get("result", {}).get("status") == "active":
                logger.info(f"Token 验证成功: {json_response}") # 记录成功信息
                return True
            else:
                # API 调用成功，但 Token 无效或状态不是 active
                logger.warning(f"Token 验证失败 (API 响应无效或状态非 active): {response.text}")
                return False
        else:
            # API 返回非 200 状态码 (例如 401 Unauthorized, 403 Forbidden)
            logger.error(f"Token 验证失败 (HTTP Status: {response.status_code}): {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        # 网络请求相关的错误 (例如超时, DNS 解析失败)
        logger.error(f"调用 Cloudflare API 时发生网络错误: {e}")
        # 可以在这里决定是返回 False 还是重新抛出异常，让调用者处理
        return False
    except Exception as e:
        # 其他未知错误 (例如 JSON 解析失败)
        logger.exception(f"验证 Token 时发生未知错误: {e}")
        return False

def get_zones_for_token(token_string):
    """
    使用 Cloudflare API /zones 端点获取 Token 权限下的域名列表。

    Args:
        token_string: Cloudflare API Token。

    Returns:
        list: 包含域名信息的字典列表 (e.g., [{'id': zone_id, 'name': zone_name, 'status': zone_status}, ...])。
              如果 API 请求失败或未找到域名，则返回空列表 []。
              出错时会打印错误信息。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    zones_url = f"{CLOUDFLARE_API_BASE_URL}/zones"
    zones = []
    page = 1

    try:
        while True: # 循环处理分页
            params = {'page': page, 'per_page': 50}
            response = requests.get(zones_url, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                json_response = response.json()
                if json_response.get("success"):
                    results = json_response.get("result", [])
                    if not results:
                        break
                    for zone in results:
                        zones.append({
                            'id': zone.get('id'),
                            'name': zone.get('name'),
                            'status': zone.get('status')
                        })
                    if len(results) < params['per_page']:
                         break
                    page += 1
                else:
                    logger.error(f"获取 Zones 失败 (API success=false): {response.text}")
                    return []
            else:
                logger.error(f"获取 Zones 失败 (HTTP Status: {response.status_code}): {response.text}")
                return []
    except requests.exceptions.RequestException as e:
        logger.error(f"调用 Cloudflare API 获取 Zones 时发生网络错误: {e}")
        return []
    
    return zones

def get_dns_records(token_string, zone_id):
    """
    获取指定 Zone 的所有 DNS 记录。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records"
    records = []
    page = 1

    try:
        while True:
            params = {'page': page, 'per_page': 100}
            response = requests.get(url, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    results = data.get("result", [])
                    if not results:
                        break
                    records.extend(results)
                    if len(results) < params['per_page']:
                        break
                    page += 1
                else:
                    logger.error(f"获取 DNS 记录失败: {data.get('errors')}")
                    return []
            else:
                logger.error(f"获取 DNS 记录失败 (HTTP {response.status_code}): {response.text}")
                return []
    except Exception as e:
        logger.exception(f"获取 DNS 记录时发生异常: {e}")
        return []

    return records

def create_dns_record(token_string, zone_id, record_data):
    """
    创建新的 DNS 记录。
    Returns: (success: bool, result: dict or str)
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records"

    try:
        response = requests.post(url, headers=headers, json=record_data, timeout=15)
        data = response.json()

        if response.status_code == 200 and data.get("success"):
            logger.info(f"DNS 记录创建成功: {data.get('result')}")
            return True, data.get("result")
        else:
            errors = data.get("errors", [])
            error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
            logger.error(f"创建 DNS 记录失败: {error_msg} | Response: {response.text}")
            return False, error_msg

    except Exception as e:
        logger.exception(f"创建 DNS 记录时发生异常: {e}")
        return False, str(e)

def delete_dns_record(token_string, zone_id, record_id):
    """
    删除 DNS 记录。
    Returns: (success: bool, message: str)
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}"

    try:
        response = requests.delete(url, headers=headers, timeout=15)
        data = response.json()

        if response.status_code == 200 and data.get("success"):
            logger.info(f"DNS 记录已删除: {record_id}")
            return True, "Success"
        else:
            errors = data.get("errors", [])
            error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
            logger.error(f"删除 DNS 记录失败: {error_msg} | Response: {response.text}")
            return False, error_msg

    except Exception as e:
        logger.exception(f"删除 DNS 记录时发生异常: {e}")
        return False, str(e)

def update_dns_record(token_string, zone_id, record_id, record_data):
    """
    更新 DNS 记录。
    Returns: (success: bool, result: dict or str)
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}"

    try:
        response = requests.put(url, headers=headers, json=record_data, timeout=15)
        data = response.json()

        if response.status_code == 200 and data.get("success"):
            logger.info(f"DNS 记录更新成功: {data.get('result')}")
            return True, data.get("result")
        else:
            errors = data.get("errors", [])
            error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
            logger.error(f"更新 DNS 记录失败: {error_msg} | Response: {response.text}")
            return False, error_msg

    except Exception as e:
        logger.exception(f"更新 DNS 记录时发生异常: {e}")
        return False, str(e)
