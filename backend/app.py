import os
import subprocess
import json
from collections import defaultdict
from fastapi import FastAPI, UploadFile, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import aiofiles # 需要 pip install aiofiles
import pyshark
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
app = FastAPI()

# 允许跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 调试期允许所有来源，上线后可指定 IP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 确保存储目录存在
UPLOAD_DIR = "storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# 定义一个全局字典，用来在内存中临时存储分析结果
analysis_results = {}

# Optimized analysis logic - try tshark first (much faster), fallback to pyshark
def heavy_trace_analysis(file_path: str, task_id: str):
    print(f"DEBUG: Starting analysis {file_path}...", flush=True)
    stats = {} # Store (src_ip, dst_ip) combination counts
    total_count = 0
    try:
        # Try using tshark command line first (much faster for large files)
        print(f"DEBUG: Attempting fast analysis with tshark...", flush=True)
        try:
            stats, total_count = analyze_with_tshark(file_path, task_id)
            print(f"DEBUG: Analysis completed with tshark, total packets: {total_count}", flush=True)
        except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
            print(f"DEBUG: tshark method failed, falling back to pyshark: {e}", flush=True)
            # Fallback to pyshark
            with pyshark.FileCapture(
                file_path, 
                display_filter='ip or ipv6', 
                keep_packets=False,
                use_json=True,  # Faster JSON parsing
                include_raw=False  # Don't include raw packet data
            ) as cap:
                stats, total_count = process_capture_in_batches(cap, batch_size=10000, task_id=task_id)
            print(f"DEBUG: Analysis completed with pyshark, total packets: {total_count}", flush=True)

        # Convert dict to DataFrame more efficiently
        if stats:
            # Use list comprehension for better performance
            data_list = [
                {"source": k[0], "destination": k[1], "count": v} 
                for k, v in stats.items()
            ]
            df = pd.DataFrame(data_list)
            
            # Sort by count
            df = df.sort_values(by="count", ascending=False)
            
            # Calculate percentage
            df["percentage"] = (df["count"] / total_count * 100).round(2).astype(str) + "%"
            
            table_data = df.to_dict(orient="records")
        else:
            table_data = []

        # Store results
        analysis_results[task_id] = {
            "status": "completed",
            "total": total_count,
            "table_data": table_data
        }
        print(f"DEBUG: Analysis results stored in analysis_results dict", flush=True)

    except Exception as e:
        print(f"ERROR: {e}", flush=True)
        analysis_results[task_id] = {"status": "error", "message": str(e)}

def process_capture_in_batches(cap, batch_size, task_id=None):
    stats = {}
    total_count = 0
    batch_count = 0
    last_update_time = 0
    
    for packet in cap:
        # Extract IP addresses more efficiently
        src = None
        dst = None
        
        # Try IPv4 first (most common)
        try:
            if hasattr(packet, 'ip'):
                src = packet.ip.src
                dst = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src = packet.ipv6.src
                dst = packet.ipv6.dst
        except AttributeError:
            # Skip packets without IP layer
            continue
        
        # Only count if we have both src and dst
        if src and dst:
            key = (src, dst)
            stats[key] = stats.get(key, 0) + 1
        
        total_count += 1
        batch_count += 1
        
        # Process batch and update progress every batch_size packets
        if batch_count >= batch_size:
            batch_count = 0
            # Update progress every 5 seconds
            import time
            current_time = time.time()
            if task_id and (current_time - last_update_time) >= 5:
                analysis_results[task_id] = {
                    "status": "processing",
                    "progress": f"Processed {total_count:,} packets...",
                    "total_processed": total_count
                }
                last_update_time = current_time
                print(f"Progress: {total_count:,} packets processed", flush=True)
    
    # Final progress update
    if task_id:
        analysis_results[task_id] = {
            "status": "processing",
            "progress": f"Finalizing... Processed {total_count:,} packets",
            "total_processed": total_count
        }
    
    return stats, total_count

# Fast analysis using tshark command line (much faster than pyshark)
def analyze_with_tshark(file_path: str, task_id: str):
    """
    Use tshark command line tool for much faster analysis.
    This is significantly faster than pyshark for large files.
    """
    stats = defaultdict(int)
    total_count = 0
    last_update_time = 0
    import time
    
    # Use tshark to extract IP pairs directly
    # -T fields: output as fields
    # -e ip.src -e ip.dst: extract source and destination IPs (empty for IPv6 packets)
    # -e ipv6.src -e ipv6.dst: extract IPv6 addresses (empty for IPv4 packets)
    # -Y "ip or ipv6": filter for IP packets only
    # -E header=n: no header
    # -E separator=\t : tab separated (more reliable)
    
    cmd = [
        'tshark',
        '-r', file_path,
        '-Y', 'ip or ipv6',
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'ipv6.src',
        '-e', 'ipv6.dst',
        '-E', 'header=n',
        '-E', 'separator=\t'
    ]
    
    print(f"DEBUG: Running tshark command...", flush=True)
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=8192  # Larger buffer for better performance
    )
    
    # Process output line by line
    for line in process.stdout:
        if not line.strip():
            continue
            
        parts = line.strip().split('\t')
        src = None
        dst = None
        
        # Check IPv4 fields first (indices 0, 1)
        if len(parts) >= 2:
            ipv4_src = parts[0].strip() if parts[0] else None
            ipv4_dst = parts[1].strip() if len(parts) > 1 and parts[1] else None
            
            if ipv4_src and ipv4_dst:
                src = ipv4_src
                dst = ipv4_dst
            # Check IPv6 fields (indices 2, 3)
            elif len(parts) >= 4:
                ipv6_src = parts[2].strip() if parts[2] else None
                ipv6_dst = parts[3].strip() if len(parts) > 3 and parts[3] else None
                
                if ipv6_src and ipv6_dst:
                    src = ipv6_src
                    dst = ipv6_dst
        
        if src and dst:
            key = (src, dst)
            stats[key] += 1
        
        total_count += 1
        
        # Update progress every 50000 packets or 5 seconds
        if total_count % 50000 == 0:
            current_time = time.time()
            if task_id and (current_time - last_update_time) >= 5:
                analysis_results[task_id] = {
                    "status": "processing",
                    "progress": f"Processed {total_count:,} packets...",
                    "total_processed": total_count
                }
                last_update_time = current_time
                print(f"Progress: {total_count:,} packets processed", flush=True)
    
    # Wait for process to complete and get stderr
    stderr_output = process.communicate()[1]
    
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, cmd, stderr_output)
    
    # Final progress update
    if task_id:
        analysis_results[task_id] = {
            "status": "processing",
            "progress": f"Finalizing... Processed {total_count:,} packets",
            "total_processed": total_count
        }
    
    return dict(stats), total_count

# Removed process_batch_stats - now processing inline for better performance

@app.get("/get_report/{task_id}")
async def get_report(task_id: str):
    return analysis_results.get(task_id, {"status": "not_found"})

@app.post("/upload")
async def upload_trace(file: UploadFile, background_tasks: BackgroundTasks):
    # 1. 验证文件后缀
    if not file.filename.endswith(('.pcapng', '.pcap')):
        raise HTTPException(status_code=400, detail="不支持的文件格式")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    # 这里的 task_id 我们直接用文件名，因为它唯一标识了这次上传
    task_id = file.filename

    # 2. Async streaming write with larger chunks for better performance
    try:
        async with aiofiles.open(file_path, 'wb') as out_file:
            # Increase chunk size to 4MB for faster upload
            while content := await file.read(4 * 1024 * 1024):
                await out_file.write(content)
    except Exception as e:
        return {"error": f"Write failed: {str(e)}"}

    # 启动后台任务，传入 task_id
    analysis_results[task_id] = {"status": "processing"}
    background_tasks.add_task(heavy_trace_analysis, file_path, task_id)
    
    return {
        "task_id": task_id,      # 必须包含这个 key
        "filename": file.filename,
        "status": "processing"
    }

@app.get("/health")
async def health_check():
    return {"status": "running"}

# 处理 Chrome DevTools 的请求，避免 404 日志
@app.get("/.well-known/appspecific/com.chrome.devtools.json")
async def chrome_devtools():
    return {"status": "not_available"}

@app.get("/api/analyze")
async def analyze_trace():
    # 1. 指定文件路径（之后我们可以改成从 S3 下载）
    file_path = "storage/VW33635_0799_20240830_140300h_Trace1Min.pcapng"
    
    # 2. 开始分析 (这里建议先分析前 10000 个包做测试，否则会很久)
    cap = pyshark.FileCapture(file_path)
    ip_counter = Counter()
    proto_counter = Counter()
    
    count = 0
    for pkt in cap:
        if count > 10000: break # 先测一万个包
        try:
            if hasattr(pkt, 'ip'):
                ip_counter[pkt.ip.src] += 1
                proto_counter[pkt.transport_layer] += 1
            elif hasattr(pkt, 'ipv6'):
                ip_counter[pkt.ipv6.src] += 1
                proto_counter[pkt.transport_layer] += 1
            count += 1
        except AttributeError:
            continue
            
    cap.close()

    # 3. 构造 Dataiku 风格的结构化数据
    return {
        "status": "success",
        "data": {
            "total_analyzed": count,
            "ip_distribution": dict(ip_counter.most_common(5)),
            "protocol_distribution": dict(proto_counter)
        }
    }

# 挂载静态页面（假设 index.html 在 frontend_static 目录下）
# 注意：这个必须在最后，因为它会捕获所有未匹配的路由
app.mount("/", StaticFiles(directory="frontend_static", html=True), name="static")