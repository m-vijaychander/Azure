import subprocess
import json
import threading
import os
import time
from datetime import datetime
from kubernetes import client, config
from flask import Flask, render_template, request, Response, redirect, url_for, jsonify

app = Flask(__name__)

# Load Kubernetes config - Updated for in-cluster configuration
try:
    # Try in-cluster config first (when running in Kubernetes)
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    print("✅ Successfully loaded in-cluster Kubernetes config")
except Exception as e:
    try:
        # Fallback to local kubeconfig (for development)
        config.load_kube_config()
        v1 = client.CoreV1Api()
        print("✅ Successfully loaded local Kubernetes config")
    except Exception as e2:
        print(f"❌ Failed to load Kubernetes config: {e2}")
        print(f"❌ In-cluster config error: {e}")
        exit(1)

# Enhanced data structures
scan_results_by_namespace = {}
scan_logs_by_namespace = {}
scan_metadata_by_namespace = {}
is_scanning_by_namespace = {}

def get_all_images(namespace):
    """Get all unique images from a namespace with debug logging"""
    images = set()
    try:
        print(f"DEBUG: Attempting to list pods in namespace: {namespace}")
        pods = v1.list_namespaced_pod(namespace)
        print(f"DEBUG: Found {len(pods.items)} pods in namespace {namespace}")
        
        for pod in pods.items:
            print(f"DEBUG: Pod {pod.metadata.name} status: {pod.status.phase}")
            if pod.spec.containers:
                for container in pod.spec.containers:
                    print(f"DEBUG: Container {container.name} image: {container.image}")
                    images.add(container.image)
            
            # Also check init containers
            if pod.spec.init_containers:
                for container in pod.spec.init_containers:
                    print(f"DEBUG: Init container {container.name} image: {container.image}")
                    images.add(container.image)
        
        print(f"DEBUG: Total unique images found: {list(images)}")
    except Exception as e:
        print(f"ERROR: Getting images from namespace {namespace}: {e}")
    return list(images)

def get_vulnerability_stats(results):
    """Calculate vulnerability statistics"""
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    total_vulns = 0
    
    for result in results:
        for vuln in result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN')
            stats[severity] = stats.get(severity, 0) + 1
            total_vulns += 1
    
    return stats, total_vulns

def scan_worker(namespace):
    """Enhanced scan worker with comprehensive debugging"""
    global scan_results_by_namespace, scan_logs_by_namespace, scan_metadata_by_namespace, is_scanning_by_namespace
    
    print(f"=== STARTING SCAN FOR NAMESPACE: {namespace} ===")
    
    # Initialize data structures
    scan_results_by_namespace[namespace] = []
    scan_logs_by_namespace[namespace] = []
    scan_metadata_by_namespace[namespace] = {
        'start_time': datetime.now().isoformat(),
        'end_time': None,
        'status': 'scanning',
        'total_images': 0,
        'scanned_images': 0,
        'failed_images': 0
    }
    is_scanning_by_namespace[namespace] = True

    try:
        images = get_all_images(namespace)
        print(f"DEBUG: Images to scan: {images}")
        scan_metadata_by_namespace[namespace]['total_images'] = len(images)
        
        if not images:
            message = f"No images found in namespace {namespace}"
            print(f"DEBUG: {message}")
            scan_logs_by_namespace[namespace].append({
                'timestamp': datetime.now().isoformat(),
                'level': 'WARNING',
                'message': message
            })
            scan_metadata_by_namespace[namespace]['status'] = 'completed'
            return

        scan_logs_by_namespace[namespace].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'INFO',
            'message': f"Found {len(images)} images to scan in namespace {namespace}"
        })

        for i, image in enumerate(images, 1):
            log_message = f"Scanning image {i}/{len(images)}: {image}"
            print(f"DEBUG: {log_message}")
            
            scan_logs_by_namespace[namespace].append({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO',
                'message': log_message
            })
            
            try:
                # Debug: Show exact command being run
                cmd = ["trivy", "image", "--quiet", "--format", "json", image]
                print(f"DEBUG: Running command: {' '.join(cmd)}")
                
                # Use universal_newlines=True for Python 3.6+ compatibility
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=300,
                    check=False  # Don't raise exception on non-zero exit
                )
                
                print(f"DEBUG: Trivy return code: {result.returncode}")
                print(f"DEBUG: Trivy stdout length: {len(result.stdout)}")
                print(f"DEBUG: Trivy stderr: {result.stderr}")
                
                # Handle non-zero return codes
                if result.returncode != 0:
                    error_msg = f"Trivy returned code {result.returncode} for {image}: {result.stderr}"
                    print(f"DEBUG: {error_msg}")
                    scan_logs_by_namespace[namespace].append({
                        'timestamp': datetime.now().isoformat(),
                        'level': 'WARNING',
                        'message': error_msg
                    })
                    # Continue processing if we got stdout anyway
                
                if not result.stdout.strip():
                    print(f"DEBUG: Empty output from trivy for image {image}")
                    scan_logs_by_namespace[namespace].append({
                        'timestamp': datetime.now().isoformat(),
                        'level': 'WARNING',
                        'message': f"Empty scan result for {image}"
                    })
                    scan_metadata_by_namespace[namespace]['scanned_images'] += 1
                    continue
                
                try:
                    scan_json = json.loads(result.stdout)
                    print(f"DEBUG: Parsed JSON keys: {list(scan_json.keys())}")
                except json.JSONDecodeError as e:
                    print(f"DEBUG: JSON decode error: {e}")
                    print(f"DEBUG: Raw output was: {result.stdout[:500]}...")
                    scan_metadata_by_namespace[namespace]['failed_images'] += 1
                    scan_logs_by_namespace[namespace].append({
                        'timestamp': datetime.now().isoformat(),
                        'level': 'ERROR',
                        'message': f"❌ Invalid JSON response for {image}: {str(e)}"
                    })
                    continue
                
                image_vulnerabilities = []
                
                # Handle different Trivy output formats
                results_list = scan_json.get("Results", [])
                if not results_list:
                    print(f"DEBUG: No 'Results' key found in JSON for {image}")
                    # Check if vulnerabilities are at root level (older Trivy versions)
                    if "Vulnerabilities" in scan_json:
                        results_list = [scan_json]
                
                for target in results_list:
                    target_name = target.get('Target', 'Unknown')
                    print(f"DEBUG: Processing target: {target_name}")
                    vulns = target.get("Vulnerabilities", [])
                    print(f"DEBUG: Found {len(vulns) if vulns else 0} vulnerabilities in target {target_name}")
                    
                    if vulns:
                        for v in vulns:
                            vuln_data = {
                                "id": v.get("VulnerabilityID", "N/A"),
                                "pkg": v.get("PkgName", "N/A"),
                                "installed": v.get("InstalledVersion", "N/A"),
                                "fixed": v.get("FixedVersion", "N/A"),
                                "severity": v.get("Severity", "UNKNOWN"),
                                "title": v.get("Title", ""),
                                "description": (v.get("Description", "")[:200] + "...") if len(v.get("Description", "")) > 200 else v.get("Description", ""),
                                "cvss_score": v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0) if isinstance(v.get("CVSS"), dict) else 0,
                                "target": target_name
                            }
                            image_vulnerabilities.append(vuln_data)
                            print(f"DEBUG: Added vulnerability: {vuln_data['id']} - {vuln_data['severity']}")
                
                print(f"DEBUG: Total vulnerabilities for {image}: {len(image_vulnerabilities)}")
                
                # Always add result, even if no vulnerabilities
                result_data = {
                    "image": image,
                    "vulnerabilities": image_vulnerabilities,
                    "scan_time": datetime.now().isoformat(),
                    "status": "success"
                }
                scan_results_by_namespace[namespace].append(result_data)
                print(f"DEBUG: Added result for {image} with {len(image_vulnerabilities)} vulnerabilities")
                
                scan_metadata_by_namespace[namespace]['scanned_images'] += 1
                scan_logs_by_namespace[namespace].append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'SUCCESS',
                    'message': f"✅ Completed scanning {image} - Found {len(image_vulnerabilities)} vulnerabilities"
                })
                
            except subprocess.TimeoutExpired:
                scan_metadata_by_namespace[namespace]['failed_images'] += 1
                error_msg = f"❌ Timeout scanning {image} (exceeded 5 minutes)"
                print(f"DEBUG: {error_msg}")
                scan_logs_by_namespace[namespace].append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'ERROR',
                    'message': error_msg
                })
            except Exception as e:
                scan_metadata_by_namespace[namespace]['failed_images'] += 1
                error_msg = f"❌ Unexpected error scanning {image}: {str(e)}"
                print(f"DEBUG: {error_msg}")
                scan_logs_by_namespace[namespace].append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'ERROR',
                    'message': error_msg
                })
    
    except Exception as e:
        error_msg = f"❌ Unexpected error in scan worker: {str(e)}"
        print(f"DEBUG: {error_msg}")
        scan_logs_by_namespace[namespace].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'ERROR',
            'message': error_msg
        })
        scan_metadata_by_namespace[namespace]['status'] = 'failed'
    finally:
        scan_metadata_by_namespace[namespace]['end_time'] = datetime.now().isoformat()
        if scan_metadata_by_namespace[namespace]['status'] != 'failed':
            scan_metadata_by_namespace[namespace]['status'] = 'completed'
        is_scanning_by_namespace[namespace] = False
        
        # Final summary log
        metadata = scan_metadata_by_namespace[namespace]
        final_msg = f"🏁 Scan completed! Images: {metadata['scanned_images']}/{metadata['total_images']}, Failed: {metadata['failed_images']}"
        print(f"DEBUG: {final_msg}")
        print(f"DEBUG: Final results count for {namespace}: {len(scan_results_by_namespace[namespace])}")
        
        scan_logs_by_namespace[namespace].append({
            'timestamp': datetime.now().isoformat(),
            'level': 'INFO',
            'message': final_msg
        })

# Rest of the Flask routes remain the same...
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        namespace = request.form["namespace"].strip()
        if not namespace:
            return render_template("index.html", 
                                 namespaces=list(scan_results_by_namespace.keys()),
                                 error="Please enter a valid namespace")
        
        if namespace not in is_scanning_by_namespace or not is_scanning_by_namespace[namespace]:
            threading.Thread(target=scan_worker, args=(namespace,), daemon=True).start()
        return redirect(url_for("scan", namespace=namespace))

    # Get scan history with metadata
    scan_history = []
    for ns in scan_results_by_namespace.keys():
        metadata = scan_metadata_by_namespace.get(ns, {})
        results = scan_results_by_namespace.get(ns, [])
        stats, total_vulns = get_vulnerability_stats(results)
        
        scan_history.append({
            'namespace': ns,
            'metadata': metadata,
            'stats': stats,
            'total_vulnerabilities': total_vulns,
            'is_scanning': is_scanning_by_namespace.get(ns, False)
        })

    return render_template("index.html", scan_history=scan_history)

@app.route("/scan/<namespace>")
def scan(namespace):
    metadata = scan_metadata_by_namespace.get(namespace, {})
    return render_template("scan.html", 
                         namespace=namespace, 
                         scanning=is_scanning_by_namespace.get(namespace, False),
                         metadata=metadata)

@app.route("/logs/<namespace>")
def stream_logs(namespace):
    def generate():
        last_index = 0
        while is_scanning_by_namespace.get(namespace, False) or last_index < len(scan_logs_by_namespace.get(namespace, [])):
            logs = scan_logs_by_namespace.get(namespace, [])
            new_logs = logs[last_index:]
            for log in new_logs:
                yield f"data: {json.dumps(log)}\n\n"
            last_index = len(logs)
            time.sleep(0.5)
        
        # Send completion signal
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/scan-status/<namespace>")
def scan_status(namespace):
    """API endpoint for scan status"""
    return jsonify({
        'scanning': is_scanning_by_namespace.get(namespace, False),
        'metadata': scan_metadata_by_namespace.get(namespace, {}),
        'log_count': len(scan_logs_by_namespace.get(namespace, []))
    })

@app.route("/results/<namespace>")
def results(namespace):
    results = scan_results_by_namespace.get(namespace, [])
    metadata = scan_metadata_by_namespace.get(namespace, {})
    stats, total_vulns = get_vulnerability_stats(results)
    
    return render_template("results.html", 
                         namespace=namespace, 
                         results=results,
                         metadata=metadata,
                         stats=stats,
                         total_vulnerabilities=total_vulns)

@app.route("/api/results/<namespace>")
def api_results(namespace):
    """API endpoint for results data"""
    results = scan_results_by_namespace.get(namespace, [])
    stats, total_vulns = get_vulnerability_stats(results)
    
    return jsonify({
        'results': results,
        'stats': stats,
        'total_vulnerabilities': total_vulns,
        'metadata': scan_metadata_by_namespace.get(namespace, {})
    })

@app.route("/debug/<namespace>")
def debug_namespace(namespace):
    """Debug endpoint to diagnose issues"""
    try:
        # Test the get_all_images function
        images = get_all_images(namespace)
        
        # Get pods directly to compare
        pods = v1.list_namespaced_pod(namespace)
        pod_info = []
        
        for pod in pods.items:
            pod_data = {
                'name': pod.metadata.name,
                'status': pod.status.phase,
                'containers': []
            }
            for container in pod.spec.containers:
                pod_data['containers'].append({
                    'name': container.name,
                    'image': container.image
                })
            pod_info.append(pod_data)
        
        # Test trivy on first image if available
        trivy_test = {}
        if images:
            test_image = images[0]
            try:
                result = subprocess.run(
                    ["trivy", "image", "--format", "json", test_image],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=60
                )
                trivy_test = {
                    'test_image': test_image,
                    'return_code': result.returncode,
                    'stdout_length': len(result.stdout),
                    'stderr': result.stderr,
                    'has_output': bool(result.stdout.strip())
                }
                
                if result.stdout:
                    try:
                        scan_json = json.loads(result.stdout)
                        trivy_test['json_keys'] = list(scan_json.keys())
                        trivy_test['results_count'] = len(scan_json.get('Results', []))
                    except json.JSONDecodeError:
                        trivy_test['json_error'] = 'Invalid JSON'
                        
            except Exception as e:
                trivy_test['error'] = str(e)
        
        return jsonify({
            'namespace': namespace,
            'images_from_function': images,
            'image_count': len(images),
            'pod_count': len(pods.items),
            'pod_details': pod_info,
            'trivy_test': trivy_test,
            'kubernetes_config': 'in-cluster' if hasattr(config, '_incluster_namespace') else 'external'
        })
    except Exception as e:
        return jsonify({'error': str(e), 'error_type': type(e).__name__})

@app.route("/test-trivy")
def test_trivy():
    """Test trivy installation and basic functionality"""
    try:
        # Test trivy version
        version_result = subprocess.run(
            ["trivy", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=10
        )
        
        # Test trivy with a simple image
        test_result = subprocess.run(
            ["trivy", "image", "--format", "json", "alpine:latest"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60
        )
        
        return jsonify({
            'trivy_version': {
                'return_code': version_result.returncode,
                'stdout': version_result.stdout,
                # Trivy Scanner AKS Deployment with ConfigMaps
