#!/usr/bin/env python
# encoding: utf-8
# @author: rockmelodies
# @license: (C) Copyright 2013-2024, 360 Corporation Limited.
# @contact: rockysocket@gmail.com
# @software: garner
# @file: pocsuite3_mcp_server.py.py
# @time: 2025/9/20 23:17
# @desc:

from mcp.server.fastmcp import FastMCP
import json
import re
import random
import string
from typing import Dict, Any

# 初始化FastMCP实例
mcp = FastMCP("PocGenius")


def generate_random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def sanitize_payload(payload):
    """确保payload安全性"""
    # 移除可能有害的命令
    harmful_patterns = [
        r'rm\s+-rf', r'mkfs', r'dd\s+if=/dev/',
        r'chmod\s+777', r'passwd', r'useradd',
        r'wget\s+-O', r'curl\s+-o', r'nc\s+-l',
        r'mv\s+.*\.php', r'cp\s+.*\.php'
    ]

    for pattern in harmful_patterns:
        payload = re.sub(pattern, '# SAFETY_REMOVED: ' + pattern, payload)

    return payload


def generate_poc_code(vuln_info: Dict[str, Any]) -> str:
    """生成pocsuite3标准POC代码"""

    # 提取漏洞信息
    title = vuln_info.get('title', 'Unknown Vulnerability')
    severity = vuln_info.get('severity', 'medium')
    description = vuln_info.get('description', '')
    vuln_type = vuln_info.get('type', 'unknown')
    request_data = vuln_info.get('request', {})
    response_data = vuln_info.get('response', {})

    # 生成随机变量
    rand_filename = generate_random_string(8) + '.txt'
    rand_boundary = generate_random_string(16)
    rand_content = generate_random_string(12)

    # 构建POC模板
    poc_template = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pocsuite3.lib.core.data import logger
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE

class TestPOC(POCBase):
    vulID = ''  # 漏洞ID
    version = '1.0'
    author = ['PocGenius']
    vulDate = '2024'
    createDate = '2024'
    updateDate = '2024'
    references = ['']
    name = "{title}"
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = {vuln_type.upper()}_TYPE
    desc = \"\"\"
{description}
    \"\"\"
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {{}}

        # 随机化参数
        random_filename = "{rand_filename}"
        random_content = "{rand_content}"

        try:
            # 构造请求
            headers = {json.dumps(request_data.get('headers', {{}}), indent=4)}
            data = {json.dumps(request_data.get('data', ''))}
            params = {json.dumps(request_data.get('params', {{}}), indent=4)}

            # 发送请求
            resp = req.{request_data.get('method', 'get').lower()}(
                self.url,
                headers=headers,
                data=data,
                params=params,
                timeout=10,
                verify=False
            )

            # 响应判断逻辑
            if resp.status_code == {response_data.get('status_code', 200)}:
                # 检查响应内容中的特征
                response_text = resp.text
                expected_patterns = {json.dumps(response_data.get('patterns', []))}

                match_found = True
                for pattern in expected_patterns:
                    if pattern not in response_text:
                        match_found = False
                        break

                if match_found:
                    result['VerifyInfo'] = {{}}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['Response'] = resp.text[:200] + '...' if len(resp.text) > 200 else resp.text

        except Exception as e:
            logger.error(f"验证过程中发生错误: {{str(e)}}")

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('目标不受影响')
        return output

register_poc(TestPOC)
'''

    return sanitize_payload(poc_template)


@mcp.tool()
def generate_poc(vuln_info: str) -> str:
    """
    根据漏洞信息生成pocsuite3标准POC

    Args:
        vuln_info: JSON格式的漏洞信息，包含title, severity, description, type, request, response等字段

    Returns:
        str: 生成的POC代码
    """
    try:
        # 解析输入的漏洞信息
        info_dict = json.loads(vuln_info)

        # 生成POC代码
        poc_code = generate_poc_code(info_dict)

        return poc_code

    except json.JSONDecodeError:
        return "错误：输入的漏洞信息必须是有效的JSON格式"
    except Exception as e:
        return f"错误：生成POC时发生异常 - {str(e)}"


@mcp.tool()
def validate_vuln_info(vuln_info: str) -> str:
    """
    验证漏洞信息的完整性和格式

    Args:
        vuln_info: JSON格式的漏洞信息

    Returns:
        str: 验证结果
    """
    try:
        info_dict = json.loads(vuln_info)
        required_fields = ['title', 'description', 'request', 'response']
        missing_fields = [field for field in required_fields if field not in info_dict]

        if missing_fields:
            return f"错误：缺少必要字段: {', '.join(missing_fields)}"

        # 检查请求信息
        if 'method' not in info_dict['request']:
            return "错误：请求信息中缺少method字段"

        return "验证通过：漏洞信息格式正确"

    except json.JSONDecodeError:
        return "错误：输入的漏洞信息必须是有效的JSON格式"


if __name__ == "__main__":
    # 运行MCP服务器

    print("pocsuite3_mcp_server MCP服务器启动中...")
    mcp.run(transport='stdio')
