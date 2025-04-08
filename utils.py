import requests
import json # 需要导入 json 来序列化请求体

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
                print(f"Token 验证成功: {json_response}") # 打印成功信息，便于调试
                return True
            else:
                # API 调用成功，但 Token 无效或状态不是 active
                print(f"Token 验证失败 (API 响应无效或状态非 active): {response.text}")
                return False
        else:
            # API 返回非 200 状态码 (例如 401 Unauthorized, 403 Forbidden)
            print(f"Token 验证失败 (HTTP Status: {response.status_code}): {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        # 网络请求相关的错误 (例如超时, DNS 解析失败)
        print(f"调用 Cloudflare API 时发生网络错误: {e}")
        # 可以在这里决定是返回 False 还是重新抛出异常，让调用者处理
        return False
    except Exception as e:
        # 其他未知错误 (例如 JSON 解析失败)
        print(f"验证 Token 时发生未知错误: {e}")
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
                    print(f"获取 Zones 失败 (API success=false): {response.text}")
                    return []
            else:
                print(f"获取 Zones 失败 (HTTP Status: {response.status_code}): {response.text}")
                return []
    except requests.exceptions.RequestException as e:
        print(f"调用 Cloudflare API 获取 Zones 时发生网络错误: {e}")
        return []
    except Exception as e:
        print(f"获取 Zones 时发生未知错误: {e}")
        return []

    print(f"成功获取 {len(zones)} 个 Zones。")
    return zones 

def get_dns_records(token_string, zone_id):
    """
    使用 Cloudflare API 获取指定 Zone 的 DNS 记录列表。

    Args:
        token_string: Cloudflare API Token。
        zone_id: 要获取记录的 Zone ID。

    Returns:
        list: 包含 DNS 记录信息的字典列表 (e.g., [{'id': record_id, 'type': 'A', ...}, ...])。
              如果 API 请求失败或未找到记录，则返回空列表 []。
              出错时会打印错误信息。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    dns_records_url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records"
    dns_records = []
    page = 1

    try:
        while True: # 循环处理分页
            params = {'page': page, 'per_page': 100}
            response = requests.get(dns_records_url, headers=headers, params=params, timeout=20)

            if response.status_code == 200:
                json_response = response.json()
                if json_response.get("success"):
                    results = json_response.get("result", [])
                    if not results:
                        break
                    for record in results:
                        # 提取我们需要的信息
                        dns_records.append({
                            'id': record.get('id'),
                            'type': record.get('type'),
                            'name': record.get('name'),
                            'content': record.get('content'),
                            'ttl': record.get('ttl'),
                            'proxied': record.get('proxied', False)
                        })
                    result_info = json_response.get("result_info", {})
                    total_pages = result_info.get("total_pages", 1)
                    current_page = result_info.get("page", 1)
                    if current_page >= total_pages:
                        break
                    page += 1
                else:
                    print(f"获取 DNS Records 失败 (API success=false, Zone: {zone_id}): {response.text}")
                    return []
            else:
                print(f"获取 DNS Records 失败 (HTTP Status: {response.status_code}, Zone: {zone_id}): {response.text}")
                return []
    except requests.exceptions.RequestException as e:
        print(f"调用 Cloudflare API 获取 DNS Records 时发生网络错误 (Zone: {zone_id}): {e}")
        return []
    except Exception as e:
        print(f"获取 DNS Records 时发生未知错误 (Zone: {zone_id}): {e}")
        return []

    print(f"成功获取 Zone {zone_id} 的 {len(dns_records)} 条 DNS 记录。")
    return dns_records 

def create_dns_record(token_string, zone_id, record_data):
    """
    使用 Cloudflare API 创建新的 DNS 记录。

    Args:
        token_string: Cloudflare API Token。
        zone_id: 要在其中创建记录的 Zone ID。
        record_data (dict): 包含 DNS 记录信息的字典，键应与 Cloudflare API 匹配
                           (e.g., {'type': 'A', 'name': 'www', 'content': '1.2.3.4', 'ttl': 1, 'proxied': False, 'priority': 10})

    Returns:
        tuple: (bool, dict/str)
               如果成功，返回 (True, 创建的记录详情 dict)。
               如果失败，返回 (False, 错误信息 str)。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    create_url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records"

    payload = {
        'type': record_data.get('type'),
        'name': record_data.get('name'),
        'content': record_data.get('content'),
        'ttl': record_data.get('ttl', 1),
        'proxied': record_data.get('proxied', False)
    }
    if payload['type'] in ['MX', 'SRV'] and record_data.get('priority') is not None:
        payload['priority'] = record_data.get('priority')

    try:
        response = requests.post(create_url, headers=headers, data=json.dumps(payload), timeout=15)

        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("success"):
                print(f"DNS 记录创建成功: {json_response.get('result')}")
                return True, json_response.get("result")
            else:
                errors = json_response.get("errors", [])
                error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors]) if errors else response.text
                print(f"创建 DNS 记录失败 (API success=false, Zone: {zone_id}): {error_message}")
                return False, f"API 错误: {error_message}"
        else:
            error_message = response.text
            try:
                errors = response.json().get("errors", [])
                if errors:
                    error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors])
            except json.JSONDecodeError:
                pass
            print(f"创建 DNS 记录失败 (HTTP Status: {response.status_code}, Zone: {zone_id}): {error_message}")
            return False, f"HTTP {response.status_code}: {error_message}"

    except requests.exceptions.RequestException as e:
        print(f"调用 Cloudflare API 创建 DNS 记录时发生网络错误 (Zone: {zone_id}): {e}")
        return False, f"网络错误: {e}"
    except Exception as e:
        print(f"创建 DNS 记录时发生未知错误 (Zone: {zone_id}): {e}")
        return False, f"未知错误: {e}" 

def delete_dns_record(token_string, zone_id, record_id):
    """
    使用 Cloudflare API 删除指定的 DNS 记录。

    Args:
        token_string: Cloudflare API Token。
        zone_id: DNS 记录所在的 Zone ID。
        record_id: 要删除的 DNS 记录的 ID。

    Returns:
        tuple: (bool, str)
               如果成功，返回 (True, "删除成功")。
               如果失败，返回 (False, 错误信息 str)。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    delete_url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}"

    try:
        response = requests.delete(delete_url, headers=headers, timeout=15)

        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("success"):
                print(f"DNS 记录删除成功 (Record ID: {record_id})")
                return True, "删除成功"
            else:
                errors = json_response.get("errors", [])
                error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors]) if errors else response.text
                print(f"删除 DNS 记录失败 (API success=false, Record ID: {record_id}): {error_message}")
                return False, f"API 错误: {error_message}"
        else:
            error_message = response.text
            try:
                errors = response.json().get("errors", [])
                if errors:
                    error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors])
            except json.JSONDecodeError:
                pass
            print(f"删除 DNS 记录失败 (HTTP Status: {response.status_code}, Record ID: {record_id}): {error_message}")
            return False, f"HTTP {response.status_code}: {error_message}"

    except requests.exceptions.RequestException as e:
        print(f"调用 Cloudflare API 删除 DNS 记录时发生网络错误 (Record ID: {record_id}): {e}")
        return False, f"网络错误: {e}"
    except Exception as e:
        print(f"删除 DNS 记录时发生未知错误 (Record ID: {record_id}): {e}")
        return False, f"未知错误: {e}" 

def update_dns_record(token_string, zone_id, record_id, updated_data):
    """
    使用 Cloudflare API 更新指定的 DNS 记录。

    Args:
        token_string: Cloudflare API Token。
        zone_id: DNS 记录所在的 Zone ID。
        record_id: 要更新的 DNS 记录的 ID。
        updated_data (dict): 包含要更新的 DNS 记录信息的字典，键应与 Cloudflare API 匹配
                             (需要包含 type, name, content, ttl, proxied, 可选 priority)。

    Returns:
        tuple: (bool, dict/str)
               如果成功，返回 (True, 更新后的记录详情 dict)。
               如果失败，返回 (False, 错误信息 str)。
    """
    headers = {
        "Authorization": f"Bearer {token_string}",
        "Content-Type": "application/json",
    }
    update_url = f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}"

    payload = {
        'type': updated_data.get('type'),
        'name': updated_data.get('name'),
        'content': updated_data.get('content'),
        'ttl': updated_data.get('ttl', 1),
        'proxied': updated_data.get('proxied', False)
    }
    if payload['type'] in ['MX', 'SRV'] and updated_data.get('priority') is not None:
        payload['priority'] = updated_data.get('priority')

    try:
        response = requests.put(update_url, headers=headers, data=json.dumps(payload), timeout=15)

        if response.status_code == 200:
            json_response = response.json()
            if json_response.get("success"):
                print(f"DNS 记录更新成功: {json_response.get('result')}")
                return True, json_response.get("result")
            else:
                errors = json_response.get("errors", [])
                error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors]) if errors else response.text
                print(f"更新 DNS 记录失败 (API success=false, Record ID: {record_id}): {error_message}")
                return False, f"API 错误: {error_message}"
        else:
            error_message = response.text
            try:
                errors = response.json().get("errors", [])
                if errors:
                    error_message = "; ".join([f"{e.get('code')}: {e.get('message')}" for e in errors])
            except json.JSONDecodeError:
                pass
            print(f"更新 DNS 记录失败 (HTTP Status: {response.status_code}, Record ID: {record_id}): {error_message}")
            return False, f"HTTP {response.status_code}: {error_message}"

    except requests.exceptions.RequestException as e:
        print(f"调用 Cloudflare API 更新 DNS 记录时发生网络错误 (Record ID: {record_id}): {e}")
        return False, f"网络错误: {e}"
    except Exception as e:
        print(f"更新 DNS 记录时发生未知错误 (Record ID: {record_id}): {e}")
        return False, f"未知错误: {e}" 