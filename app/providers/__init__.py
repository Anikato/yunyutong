# DNS Provider 工厂模块
from .base import DNSProvider
from .cloudflare import CloudflareProvider
from .aliyun import AliyunProvider

# 支持的 Provider 类型映射
PROVIDER_CLASSES = {
    'cloudflare': CloudflareProvider,
    'aliyun': AliyunProvider,
}

# Provider 选项（用于表单下拉框）
PROVIDER_CHOICES = [
    ('cloudflare', 'Cloudflare'),
    ('aliyun', '阿里云 DNS'),
]

def get_provider(provider_type: str, credentials: dict) -> DNSProvider:
    """
    工厂方法：根据 provider_type 获取对应的 DNS Provider 实例
    
    Args:
        provider_type: Provider 类型标识符 (e.g., 'cloudflare', 'aliyun')
        credentials: 凭证字典，不同 provider 需要不同的凭证
            - Cloudflare: {'api_token': 'xxx'}
            - 阿里云: {'access_key_id': 'xxx', 'access_key_secret': 'xxx'}
    
    Returns:
        DNSProvider 子类实例
    
    Raises:
        ValueError: 如果 provider_type 不支持
    """
    provider_class = PROVIDER_CLASSES.get(provider_type)
    if not provider_class:
        raise ValueError(f"不支持的 DNS Provider 类型: {provider_type}")
    return provider_class(credentials)

def get_provider_name(provider_type: str) -> str:
    """获取 Provider 的显示名称"""
    for code, name in PROVIDER_CHOICES:
        if code == provider_type:
            return name
    return provider_type

def get_credential_fields(provider_type: str) -> list:
    """
    获取指定 Provider 需要的凭证字段信息
    用于动态生成表单
    """
    provider_class = PROVIDER_CLASSES.get(provider_type)
    if provider_class:
        return provider_class.get_credential_fields()
    return []
