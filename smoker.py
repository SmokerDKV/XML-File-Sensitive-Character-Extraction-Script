import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, unquote

def extract_fuzz_dict_from_burp_xml(xml_file, output_file):
    """
    从Burp Suite导出的XML中提取Fuzz字典（增强版）
    """
    fuzz_dict = set()
    param_names = set()
    
    try:
        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 提取所有URL
        urls = re.findall(r'<url><!\[CDATA\[(.*?)\]\]></url>', content, re.DOTALL)
        # 提取所有请求
        requests = re.findall(r'<request.*?><!\[CDATA\[(.*?)\]\]></request>', content, re.DOTALL)
        # 提取所有响应
        responses = re.findall(r'<response.*?><!\[CDATA\[(.*?)\]\]></response>', content, re.DOTALL)
        
        print(f"✅ 找到 {len(urls)} 个URL")
        print(f"✅ 找到 {len(requests)} 个请求")
        print(f"✅ 找到 {len(responses)} 个响应")
        
        # 处理URL
        for url in urls:
            process_url_enhanced(url, fuzz_dict, param_names)
        
        # 处理请求
        for req in requests:
            process_request_enhanced(req, fuzz_dict, param_names)
        
        # 处理响应（提取有价值的字符串）
        for resp in responses:
            process_response_enhanced(resp, fuzz_dict)
        
        # 去重并过滤
        filtered_dict = set()
        for item in fuzz_dict:
            # 过滤条件
            if (len(item) >= 2 and len(item) <= 30 and  # 长度控制
                not re.match(r'^\d+$', item) and  # 排除纯数字
                not re.match(r'^[a-f0-9]{16,}$', item) and  # 排除哈希
                not re.match(r'^[A-Za-z]+$', item) or len(item) >= 4):  # 英文单词至少4字符
                filtered_dict.add(item)
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            for item in sorted(filtered_dict, key=lambda x: (len(x), x)):
                f.write(item + '\n')
        
        print(f"\n✅ 成功生成 {len(filtered_dict)} 条Fuzz字典")
        print(f"📁 保存到: {output_file}")
        
        # 显示分类统计
        print(f"\n📊 提取统计:")
        print(f"   - 参数名: {len(param_names)}")
        print(f"   - 总字典项: {len(filtered_dict)}")
        
        # 显示前30条预览
        print(f"\n📋 字典预览（前30条）:")
        for i, item in enumerate(sorted(filtered_dict)[:30]):
            print(f"   {i+1}. {item}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")

def process_url_enhanced(url, fuzz_dict, param_names):
    """处理URL"""
    try:
        parsed = urlparse(url)
        
        # 提取参数名和值
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                if 2 <= len(param_name) <= 20:
                    param_names.add(param_name)
                    fuzz_dict.add(param_name)
                    fuzz_dict.add(f"{param_name}=FUZZ")
                for value in values:
                    if value and 2 <= len(value) <= 20:
                        fuzz_dict.add(value)
        
        # 提取路径中的目录名（通常是API端点）
        path_parts = [p for p in parsed.path.split('/') if p and len(p) >= 3]
        for part in path_parts:
            # 过滤常见文件扩展名
            if not re.search(r'\.(html|htm|php|asp|aspx|jsp|txt|xml|json)$', part):
                fuzz_dict.add(part)
                # 如果是常见API模式，添加FUZZ占位符
                if part in ['api', 'v1', 'v2', 'admin', 'user']:
                    fuzz_dict.add(f"{part}/FUZZ")
        
        # 提取文件名（不含扩展名）
        filename = parsed.path.split('/')[-1]
        if '.' in filename:
            name_without_ext = filename.split('.')[0]
            if len(name_without_ext) >= 3:
                fuzz_dict.add(name_without_ext)
        
        # 提取扩展名
        ext_match = re.search(r'\.([a-z]{2,4})$', parsed.path.lower())
        if ext_match:
            ext = ext_match.group(1)
            if ext not in ['html', 'htm', 'css', 'js', 'jpg', 'png', 'gif', 'ico', 'svg']:
                fuzz_dict.add(f"FUZZ.{ext}")
                
    except Exception as e:
        pass

def process_request_enhanced(request_text, fuzz_dict, param_names):
    """处理HTTP请求"""
    try:
        # 提取请求行中的路径和参数
        lines = request_text.split('\n')
        if lines:
            request_line = lines[0]
            
            # 提取GET参数
            if '?' in request_line:
                query_part = request_line.split('?')[1].split(' ')[0]
                params = parse_qs(query_part)
                for param_name, values in params.items():
                    if 2 <= len(param_name) <= 20:
                        param_names.add(param_name)
                        fuzz_dict.add(param_name)
                        fuzz_dict.add(f"{param_name}=FUZZ")
                    for value in values:
                        if value and 2 <= len(value) <= 20:
                            fuzz_dict.add(value)
            
            # 提取路径中的关键信息
            path_match = re.search(r'\w+\s+([^\s?]+)', request_line)
            if path_match:
                path = path_match.group(1)
                # 提取路径中的单词
                words = re.findall(r'/([a-zA-Z][a-zA-Z0-9_-]{2,})', path)
                for word in words:
                    if word.lower() not in ['index', 'main', 'default', 'home']:
                        fuzz_dict.add(word)
        
        # 提取POST参数
        body_match = re.search(r'\r\n\r\n(.*)$', request_text, re.DOTALL)
        if body_match:
            body = body_match.group(1)
            # 提取参数名=参数值格式
            post_params = re.findall(r'(\w+)=([^&\s]+)', body)
            for param_name, param_value in post_params:
                if 2 <= len(param_name) <= 20:
                    param_names.add(param_name)
                    fuzz_dict.add(param_name)
                    fuzz_dict.add(f"{param_name}=FUZZ")
                if param_value and 2 <= len(param_value) <= 20:
                    fuzz_dict.add(param_value)
        
        # 提取Cookie
        cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', request_text, re.IGNORECASE)
        if cookie_match:
            cookies = cookie_match.group(1).split(';')
            for cookie in cookies:
                if '=' in cookie:
                    cookie_name = cookie.split('=')[0].strip()
                    if 2 <= len(cookie_name) <= 20:
                        fuzz_dict.add(cookie_name)
                        fuzz_dict.add(f"{cookie_name}=FUZZ")
        
        # 提取其他Header
        headers = ['User-Agent', 'Referer', 'Origin', 'X-Forwarded-For', 'X-Requested-With', 'Accept-Language']
        for header in headers:
            header_match = re.search(f'{header}:\s*([^\r\n]+)', request_text, re.IGNORECASE)
            if header_match:
                header_value = header_match.group(1).strip()
                if 3 <= len(header_value) <= 25:
                    # 提取有意义的单词
                    words = re.findall(r'([a-zA-Z]{3,})', header_value)
                    for word in words[:3]:  # 限制数量
                        if word.lower() not in ['get', 'post', 'http', 'https', 'com', 'net', 'org']:
                            fuzz_dict.add(word.lower())
                            
    except Exception as e:
        pass

def process_response_enhanced(response_text, fuzz_dict):
    """处理HTTP响应，提取有价值的信息"""
    try:
        # 提取服务器类型
        server_match = re.search(r'Server:\s*([^\r\n]+)', response_text, re.IGNORECASE)
        if server_match:
            server = server_match.group(1).strip()
            if len(server) <= 20:
                fuzz_dict.add(server)
        
        # 提取Set-Cookie中的cookie名
        set_cookies = re.findall(r'Set-Cookie:\s*([^=;]+)=', response_text, re.IGNORECASE)
        for cookie_name in set_cookies:
            if 2 <= len(cookie_name) <= 20:
                fuzz_dict.add(cookie_name)
                fuzz_dict.add(f"{cookie_name}=FUZZ")
        
        # 提取响应体中的URL路径
        urls_in_response = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', response_text, re.IGNORECASE)
        for url_path in urls_in_response:
            if url_path.startswith('/') and 3 <= len(url_path) <= 30:
                # 提取路径中的关键词
                parts = [p for p in url_path.split('/') if p and len(p) >= 3]
                for part in parts[:3]:
                    if not re.search(r'\.(css|js|png|jpg|gif|ico)$', part):
                        fuzz_dict.add(part)
        
        # 提取JSON格式的字段名
        json_fields = re.findall(r'"(\w+)":', response_text)
        for field in json_fields:
            if 3 <= len(field) <= 20:
                fuzz_dict.add(field)
        
        # 提取常见错误信息中的路径
        error_paths = re.findall(r'(?:file|path|directory|folder):\s*[\'"]?([^\'"\s]+)', response_text, re.IGNORECASE)
        for path in error_paths:
            if path.startswith('/') and 3 <= len(path) <= 30:
                fuzz_dict.add(path.split('/')[-1])
                
    except Exception as e:
        pass

if __name__ == "__main__":
    extract_fuzz_dict_from_burp_xml("baidu.xml", "output.txt")