# DNS Provider 抽象基类
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DNSProvider(ABC):
    """
    DNS Provider 抽象基类
    所有 DNS 服务商的实现都需要继承此类
    """
    
    # Provider 标识符
    provider_type: str = ""
    # Provider 显示名称
    display_name: str = ""
    
    def __init__(self, credentials: dict):
        """
        初始化 Provider
        
        Args:
            credentials: 凭证字典，具体字段由子类定义
        """
        self.credentials = credentials
        self._validate_credentials()
    
    @abstractmethod
    def _validate_credentials(self) -> None:
        """
        验证凭证是否完整
        子类必须实现此方法
        
        Raises:
            ValueError: 凭证不完整时抛出
        """
        pass
    
    @classmethod
    @abstractmethod
    def get_credential_fields(cls) -> List[Dict[str, Any]]:
        """
        获取此 Provider 需要的凭证字段信息
        用于动态生成表单
        
        Returns:
            字段列表，每个字段包含:
            - name: 字段名
            - label: 显示标签
            - type: 字段类型 (text, password, textarea)
            - required: 是否必填
            - placeholder: 占位符文本
            - help_text: 帮助文本
        """
        pass
    
    @abstractmethod
    def verify_credentials(self) -> bool:
        """
        验证凭证是否有效（调用 API 验证）
        
        Returns:
            bool: 凭证有效返回 True，否则返回 False
        """
        pass
    
    @abstractmethod
    def get_zones(self) -> List[Dict[str, Any]]:
        """
        获取所有域名（Zone）列表
        
        Returns:
            域名列表，每个域名包含:
            - id: 域名唯一标识
            - name: 域名名称
            - status: 域名状态
        """
        pass
    
    @abstractmethod
    def get_dns_records(self, zone_id: str) -> List[Dict[str, Any]]:
        """
        获取指定域名的所有 DNS 记录
        
        Args:
            zone_id: 域名标识符
        
        Returns:
            DNS 记录列表，每条记录包含:
            - id: 记录唯一标识
            - type: 记录类型 (A, AAAA, CNAME, TXT, MX, etc.)
            - name: 记录名称（主机记录）
            - content: 记录值
            - ttl: TTL 值
            - proxied: 是否代理（仅 Cloudflare）
            - priority: 优先级（MX, SRV 记录）
        """
        pass
    
    @abstractmethod
    def create_dns_record(self, zone_id: str, record_data: dict) -> Tuple[bool, Any]:
        """
        创建 DNS 记录
        
        Args:
            zone_id: 域名标识符
            record_data: 记录数据，包含 type, name, content, ttl 等
        
        Returns:
            (success, result): 成功时 result 为创建的记录信息，失败时为错误消息
        """
        pass
    
    @abstractmethod
    def update_dns_record(self, zone_id: str, record_id: str, record_data: dict) -> Tuple[bool, Any]:
        """
        更新 DNS 记录
        
        Args:
            zone_id: 域名标识符
            record_id: 记录标识符
            record_data: 要更新的记录数据
        
        Returns:
            (success, result): 成功时 result 为更新后的记录信息，失败时为错误消息
        """
        pass
    
    @abstractmethod
    def delete_dns_record(self, zone_id: str, record_id: str) -> Tuple[bool, str]:
        """
        删除 DNS 记录
        
        Args:
            zone_id: 域名标识符
            record_id: 记录标识符
        
        Returns:
            (success, message): 操作结果
        """
        pass
    
    def get_supported_record_types(self) -> List[Tuple[str, str]]:
        """
        获取此 Provider 支持的 DNS 记录类型
        子类可以覆盖此方法
        
        Returns:
            记录类型列表，每个元素为 (type_code, type_display_name)
        """
        return [
            ('A', 'A (IPv4 Address)'),
            ('AAAA', 'AAAA (IPv6 Address)'),
            ('CNAME', 'CNAME (Canonical Name)'),
            ('TXT', 'TXT (Text Record)'),
            ('MX', 'MX (Mail Exchange)'),
            ('NS', 'NS (Name Server)'),
        ]
    
    def get_ttl_choices(self) -> List[Tuple[int, str]]:
        """
        获取此 Provider 支持的 TTL 选项
        子类可以覆盖此方法
        
        Returns:
            TTL 选项列表，每个元素为 (ttl_value, display_name)
        """
        return [
            (600, '10 分钟'),
            (1800, '30 分钟'),
            (3600, '1 小时'),
            (43200, '12 小时'),
            (86400, '1 天'),
        ]
    
    def supports_proxy(self) -> bool:
        """
        是否支持代理功能（如 Cloudflare 的橙色云）
        
        Returns:
            bool: 支持返回 True
        """
        return False
