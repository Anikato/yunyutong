# Cloudflare DNS Provider 实现
import requests
import logging
from typing import List, Dict, Tuple, Any
from .base import DNSProvider

logger = logging.getLogger(__name__)

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareProvider(DNSProvider):
    """Cloudflare DNS Provider 实现"""
    
    provider_type = "cloudflare"
    display_name = "Cloudflare"
    
    def _validate_credentials(self) -> None:
        """验证凭证完整性"""
        if not self.credentials.get('api_token'):
            raise ValueError("Cloudflare 需要提供 API Token")
    
    @classmethod
    def get_credential_fields(cls) -> List[Dict[str, Any]]:
        """获取凭证字段信息"""
        return [
            {
                'name': 'api_token',
                'label': 'API Token',
                'type': 'textarea',
                'required': True,
                'placeholder': '粘贴你的 Cloudflare API Token...',
                'help_text': '在 Cloudflare 控制台 → My Profile → API Tokens 中创建',
            }
        ]
    
    def _get_headers(self) -> dict:
        """获取 API 请求头"""
        return {
            "Authorization": f"Bearer {self.credentials['api_token']}",
            "Content-Type": "application/json",
        }
    
    def verify_credentials(self) -> bool:
        """验证 API Token 是否有效"""
        try:
            response = requests.get(
                f"{CLOUDFLARE_API_BASE_URL}/user/tokens/verify",
                headers=self._get_headers(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("result", {}).get("status") == "active":
                    logger.info("Cloudflare Token 验证成功")
                    return True
            
            logger.warning(f"Cloudflare Token 验证失败: {response.text}")
            return False
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Cloudflare API 网络错误: {e}")
            return False
        except Exception as e:
            logger.exception(f"Cloudflare Token 验证异常: {e}")
            return False
    
    def get_zones(self) -> List[Dict[str, Any]]:
        """获取所有域名列表"""
        zones = []
        page = 1
        
        try:
            while True:
                params = {'page': page, 'per_page': 50}
                response = requests.get(
                    f"{CLOUDFLARE_API_BASE_URL}/zones",
                    headers=self._get_headers(),
                    params=params,
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        results = data.get("result", [])
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
                        logger.error(f"获取 Cloudflare Zones 失败: {response.text}")
                        return []
                else:
                    logger.error(f"获取 Cloudflare Zones 失败 (HTTP {response.status_code}): {response.text}")
                    return []
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"获取 Cloudflare Zones 网络错误: {e}")
            return []
        
        return zones
    
    def get_dns_records(self, zone_id: str) -> List[Dict[str, Any]]:
        """获取指定域名的 DNS 记录"""
        records = []
        page = 1
        
        try:
            while True:
                params = {'page': page, 'per_page': 100}
                response = requests.get(
                    f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records",
                    headers=self._get_headers(),
                    params=params,
                    timeout=15
                )
                
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
                        logger.error(f"获取 Cloudflare DNS 记录失败: {data.get('errors')}")
                        return []
                else:
                    logger.error(f"获取 Cloudflare DNS 记录失败 (HTTP {response.status_code}): {response.text}")
                    return []
                    
        except Exception as e:
            logger.exception(f"获取 Cloudflare DNS 记录异常: {e}")
            return []
        
        return records
    
    def create_dns_record(self, zone_id: str, record_data: dict) -> Tuple[bool, Any]:
        """创建 DNS 记录"""
        try:
            response = requests.post(
                f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records",
                headers=self._get_headers(),
                json=record_data,
                timeout=15
            )
            data = response.json()
            
            if response.status_code == 200 and data.get("success"):
                logger.info(f"Cloudflare DNS 记录创建成功: {data.get('result')}")
                return True, data.get("result")
            else:
                errors = data.get("errors", [])
                error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
                logger.error(f"创建 Cloudflare DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"创建 Cloudflare DNS 记录异常: {e}")
            return False, str(e)
    
    def update_dns_record(self, zone_id: str, record_id: str, record_data: dict) -> Tuple[bool, Any]:
        """更新 DNS 记录"""
        try:
            response = requests.put(
                f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}",
                headers=self._get_headers(),
                json=record_data,
                timeout=15
            )
            data = response.json()
            
            if response.status_code == 200 and data.get("success"):
                logger.info(f"Cloudflare DNS 记录更新成功: {data.get('result')}")
                return True, data.get("result")
            else:
                errors = data.get("errors", [])
                error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
                logger.error(f"更新 Cloudflare DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"更新 Cloudflare DNS 记录异常: {e}")
            return False, str(e)
    
    def delete_dns_record(self, zone_id: str, record_id: str) -> Tuple[bool, str]:
        """删除 DNS 记录"""
        try:
            response = requests.delete(
                f"{CLOUDFLARE_API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}",
                headers=self._get_headers(),
                timeout=15
            )
            data = response.json()
            
            if response.status_code == 200 and data.get("success"):
                logger.info(f"Cloudflare DNS 记录已删除: {record_id}")
                return True, "Success"
            else:
                errors = data.get("errors", [])
                error_msg = "; ".join([e.get("message", "未知错误") for e in errors])
                logger.error(f"删除 Cloudflare DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"删除 Cloudflare DNS 记录异常: {e}")
            return False, str(e)
    
    def get_supported_record_types(self) -> List[Tuple[str, str]]:
        """Cloudflare 支持的 DNS 记录类型"""
        return [
            ('A', 'A (IPv4 Address)'),
            ('AAAA', 'AAAA (IPv6 Address)'),
            ('CNAME', 'CNAME (Canonical Name)'),
            ('TXT', 'TXT (Text Record)'),
            ('MX', 'MX (Mail Exchange)'),
            ('SRV', 'SRV (Service Record)'),
            ('NS', 'NS (Name Server)'),
        ]
    
    def get_ttl_choices(self) -> List[Tuple[int, str]]:
        """Cloudflare 支持的 TTL 选项"""
        return [
            (1, 'Auto'),
            (60, '1 分钟'),
            (120, '2 分钟'),
            (300, '5 分钟'),
            (600, '10 分钟'),
            (900, '15 分钟'),
            (1800, '30 分钟'),
            (3600, '1 小时'),
            (7200, '2 小时'),
            (18000, '5 小时'),
            (43200, '12 小时'),
            (86400, '1 天'),
        ]
    
    def supports_proxy(self) -> bool:
        """Cloudflare 支持代理功能"""
        return True
