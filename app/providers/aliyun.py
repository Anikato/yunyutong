# 阿里云 DNS Provider 实现
import logging
from typing import List, Dict, Tuple, Any
from .base import DNSProvider

logger = logging.getLogger(__name__)

# 阿里云 SDK 可能未安装，延迟导入
ALIYUN_SDK_AVAILABLE = False
try:
    from alibabacloud_alidns20150109.client import Client as AlidnsClient
    from alibabacloud_tea_openapi import models as open_api_models
    from alibabacloud_alidns20150109 import models as alidns_models
    from alibabacloud_tea_util import models as util_models
    ALIYUN_SDK_AVAILABLE = True
except ImportError:
    logger.warning("阿里云 DNS SDK 未安装。如需使用阿里云 DNS，请安装: pip install alibabacloud_alidns20150109")


class AliyunProvider(DNSProvider):
    """阿里云 DNS Provider 实现"""
    
    provider_type = "aliyun"
    display_name = "阿里云 DNS"
    
    def __init__(self, credentials: dict):
        super().__init__(credentials)
        self._client = None
    
    def _validate_credentials(self) -> None:
        """验证凭证完整性"""
        if not self.credentials.get('access_key_id'):
            raise ValueError("阿里云需要提供 Access Key ID")
        if not self.credentials.get('access_key_secret'):
            raise ValueError("阿里云需要提供 Access Key Secret")
    
    @classmethod
    def get_credential_fields(cls) -> List[Dict[str, Any]]:
        """获取凭证字段信息"""
        return [
            {
                'name': 'access_key_id',
                'label': 'Access Key ID',
                'type': 'text',
                'required': True,
                'placeholder': '输入 AccessKey ID...',
                'help_text': '在阿里云控制台 → AccessKey 管理中获取',
            },
            {
                'name': 'access_key_secret',
                'label': 'Access Key Secret',
                'type': 'password',
                'required': True,
                'placeholder': '输入 AccessKey Secret...',
                'help_text': '请妥善保管，不要泄露给他人',
            }
        ]
    
    def _get_client(self) -> 'AlidnsClient':
        """获取阿里云 DNS 客户端"""
        if not ALIYUN_SDK_AVAILABLE:
            raise RuntimeError("阿里云 DNS SDK 未安装，请运行: pip install alibabacloud_alidns20150109")
        
        if self._client is None:
            config = open_api_models.Config(
                access_key_id=self.credentials['access_key_id'],
                access_key_secret=self.credentials['access_key_secret']
            )
            config.endpoint = 'alidns.cn-hangzhou.aliyuncs.com'
            self._client = AlidnsClient(config)
        
        return self._client
    
    def verify_credentials(self) -> bool:
        """验证凭证是否有效"""
        if not ALIYUN_SDK_AVAILABLE:
            logger.error("阿里云 DNS SDK 未安装")
            return False
        
        try:
            client = self._get_client()
            # 尝试获取域名列表来验证凭证
            request = alidns_models.DescribeDomainsRequest(page_number=1, page_size=1)
            runtime = util_models.RuntimeOptions()
            response = client.describe_domains_with_options(request, runtime)
            
            if response.status_code == 200:
                logger.info("阿里云 DNS 凭证验证成功")
                return True
            
            logger.warning(f"阿里云 DNS 凭证验证失败")
            return False
            
        except Exception as e:
            logger.error(f"阿里云 DNS 凭证验证异常: {e}")
            return False
    
    def get_zones(self) -> List[Dict[str, Any]]:
        """获取所有域名列表"""
        if not ALIYUN_SDK_AVAILABLE:
            logger.error("阿里云 DNS SDK 未安装")
            return []
        
        zones = []
        page = 1
        page_size = 50
        
        try:
            client = self._get_client()
            runtime = util_models.RuntimeOptions()
            
            while True:
                request = alidns_models.DescribeDomainsRequest(
                    page_number=page,
                    page_size=page_size
                )
                response = client.describe_domains_with_options(request, runtime)
                
                if response.status_code == 200:
                    body = response.body
                    domains = body.domains.domain if body.domains else []
                    
                    if not domains:
                        break
                    
                    for domain in domains:
                        zones.append({
                            'id': domain.domain_name,  # 阿里云用域名作为标识
                            'name': domain.domain_name,
                            'status': 'ENABLE' if domain.dns_servers else 'active'
                        })
                    
                    total = body.total_count or 0
                    if page * page_size >= total:
                        break
                    page += 1
                else:
                    logger.error(f"获取阿里云域名列表失败")
                    return []
                    
        except Exception as e:
            logger.exception(f"获取阿里云域名列表异常: {e}")
            return []
        
        return zones
    
    def get_dns_records(self, zone_id: str) -> List[Dict[str, Any]]:
        """获取指定域名的 DNS 记录"""
        if not ALIYUN_SDK_AVAILABLE:
            logger.error("阿里云 DNS SDK 未安装")
            return []
        
        records = []
        page = 1
        page_size = 100
        
        try:
            client = self._get_client()
            runtime = util_models.RuntimeOptions()
            
            while True:
                request = alidns_models.DescribeDomainRecordsRequest(
                    domain_name=zone_id,  # zone_id 在阿里云就是域名
                    page_number=page,
                    page_size=page_size
                )
                response = client.describe_domain_records_with_options(request, runtime)
                
                if response.status_code == 200:
                    body = response.body
                    domain_records = body.domain_records.record if body.domain_records else []
                    
                    if not domain_records:
                        break
                    
                    for record in domain_records:
                        # 转换为统一格式
                        full_name = f"{record.rr}.{zone_id}" if record.rr != '@' else zone_id
                        records.append({
                            'id': record.record_id,
                            'type': record.type,
                            'name': full_name,
                            'rr': record.rr,  # 保留原始主机记录
                            'content': record.value,
                            'ttl': record.ttl,
                            'proxied': False,  # 阿里云不支持代理
                            'priority': record.priority if hasattr(record, 'priority') else None,
                            'line': record.line if hasattr(record, 'line') else 'default',
                            'status': record.status if hasattr(record, 'status') else 'ENABLE',
                        })
                    
                    total = body.total_count or 0
                    if page * page_size >= total:
                        break
                    page += 1
                else:
                    logger.error(f"获取阿里云 DNS 记录失败")
                    return []
                    
        except Exception as e:
            logger.exception(f"获取阿里云 DNS 记录异常: {e}")
            return []
        
        return records
    
    def create_dns_record(self, zone_id: str, record_data: dict) -> Tuple[bool, Any]:
        """创建 DNS 记录"""
        if not ALIYUN_SDK_AVAILABLE:
            return False, "阿里云 DNS SDK 未安装"
        
        try:
            client = self._get_client()
            runtime = util_models.RuntimeOptions()
            
            # 从 name 提取主机记录 (RR)
            name = record_data.get('name', '@')
            rr = self._extract_rr(name, zone_id)
            
            request = alidns_models.AddDomainRecordRequest(
                domain_name=zone_id,
                rr=rr,
                type=record_data.get('type'),
                value=record_data.get('content'),
                ttl=record_data.get('ttl', 600),
                priority=record_data.get('priority') if record_data.get('type') in ['MX', 'SRV'] else None,
            )
            
            response = client.add_domain_record_with_options(request, runtime)
            
            if response.status_code == 200:
                result = {
                    'id': response.body.record_id,
                    'type': record_data.get('type'),
                    'name': name,
                    'content': record_data.get('content'),
                    'ttl': record_data.get('ttl', 600),
                }
                logger.info(f"阿里云 DNS 记录创建成功: {result}")
                return True, result
            else:
                error_msg = "创建失败"
                logger.error(f"创建阿里云 DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"创建阿里云 DNS 记录异常: {e}")
            error_msg = str(e)
            # 提取更友好的错误信息
            if 'InvalidDomainName' in error_msg:
                error_msg = "无效的域名"
            elif 'DomainRecordDuplicate' in error_msg:
                error_msg = "DNS 记录已存在"
            return False, error_msg
    
    def update_dns_record(self, zone_id: str, record_id: str, record_data: dict) -> Tuple[bool, Any]:
        """更新 DNS 记录"""
        if not ALIYUN_SDK_AVAILABLE:
            return False, "阿里云 DNS SDK 未安装"
        
        try:
            client = self._get_client()
            runtime = util_models.RuntimeOptions()
            
            # 从 name 提取主机记录 (RR)
            name = record_data.get('name', '@')
            rr = self._extract_rr(name, zone_id)
            
            request = alidns_models.UpdateDomainRecordRequest(
                record_id=record_id,
                rr=rr,
                type=record_data.get('type'),
                value=record_data.get('content'),
                ttl=record_data.get('ttl', 600),
                priority=record_data.get('priority') if record_data.get('type') in ['MX', 'SRV'] else None,
            )
            
            response = client.update_domain_record_with_options(request, runtime)
            
            if response.status_code == 200:
                result = {
                    'id': record_id,
                    'type': record_data.get('type'),
                    'name': name,
                    'content': record_data.get('content'),
                    'ttl': record_data.get('ttl', 600),
                }
                logger.info(f"阿里云 DNS 记录更新成功: {result}")
                return True, result
            else:
                error_msg = "更新失败"
                logger.error(f"更新阿里云 DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"更新阿里云 DNS 记录异常: {e}")
            return False, str(e)
    
    def delete_dns_record(self, zone_id: str, record_id: str) -> Tuple[bool, str]:
        """删除 DNS 记录"""
        if not ALIYUN_SDK_AVAILABLE:
            return False, "阿里云 DNS SDK 未安装"
        
        try:
            client = self._get_client()
            runtime = util_models.RuntimeOptions()
            
            request = alidns_models.DeleteDomainRecordRequest(record_id=record_id)
            response = client.delete_domain_record_with_options(request, runtime)
            
            if response.status_code == 200:
                logger.info(f"阿里云 DNS 记录已删除: {record_id}")
                return True, "Success"
            else:
                error_msg = "删除失败"
                logger.error(f"删除阿里云 DNS 记录失败: {error_msg}")
                return False, error_msg
                
        except Exception as e:
            logger.exception(f"删除阿里云 DNS 记录异常: {e}")
            return False, str(e)
    
    def _extract_rr(self, name: str, domain: str) -> str:
        """
        从完整域名中提取主机记录 (RR)
        例如: www.example.com -> www, example.com -> @
        """
        if name == domain or name == '@':
            return '@'
        if name.endswith('.' + domain):
            return name[:-len('.' + domain)]
        return name
    
    def get_supported_record_types(self) -> List[Tuple[str, str]]:
        """阿里云支持的 DNS 记录类型"""
        return [
            ('A', 'A (IPv4 Address)'),
            ('AAAA', 'AAAA (IPv6 Address)'),
            ('CNAME', 'CNAME (Canonical Name)'),
            ('TXT', 'TXT (Text Record)'),
            ('MX', 'MX (Mail Exchange)'),
            ('NS', 'NS (Name Server)'),
            ('SRV', 'SRV (Service Record)'),
            ('CAA', 'CAA (Certificate Authority)'),
            ('REDIRECT_URL', 'URL 显性转发'),
            ('FORWARD_URL', 'URL 隐性转发'),
        ]
    
    def get_ttl_choices(self) -> List[Tuple[int, str]]:
        """阿里云支持的 TTL 选项"""
        return [
            (600, '10 分钟'),
            (1800, '30 分钟'),
            (3600, '1 小时'),
            (43200, '12 小时'),
            (86400, '1 天'),
        ]
    
    def supports_proxy(self) -> bool:
        """阿里云不支持代理功能"""
        return False
