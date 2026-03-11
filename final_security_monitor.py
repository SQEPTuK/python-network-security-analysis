import json
import os
from pathlib import Path
from typing import List, Dict, Any

import pandas as pd
import requests
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / 'output'
LOG_FILE = BASE_DIR / 'suricata_eve.jsonl'
REPORT_CSV = OUTPUT_DIR / 'report.csv'
REPORT_JSON = OUTPUT_DIR / 'report.json'
CHART_PNG = OUTPUT_DIR / 'top_suspicious_ips.png'

VT_API_KEY = os.getenv('VT_API_KEY', '').strip()
VULNERS_API_KEY = os.getenv('VULNERS_API_KEY', '').strip()

DEMO_VULNERS = [
    {
        'id': 'CVE-2024-21762',
        'title': 'Fortinet FortiOS SSL VPN Out-of-Bounds Write',
        'cvss': 9.6,
        'published': '2024-02-08T00:00:00',
        'source': 'demo_vulners'
    },
    {
        'id': 'CVE-2023-22527',
        'title': 'Atlassian Confluence Template Injection',
        'cvss': 10.0,
        'published': '2024-01-16T00:00:00',
        'source': 'demo_vulners'
    },
    {
        'id': 'CVE-2024-3400',
        'title': 'PAN-OS GlobalProtect Command Injection',
        'cvss': 10.0,
        'published': '2024-04-12T00:00:00',
        'source': 'demo_vulners'
    },
]

DEMO_VT = {
    '203.0.113.10': {'malicious': 7, 'suspicious': 2, 'harmless': 10, 'source': 'demo_virustotal'},
    '198.51.100.25': {'malicious': 0, 'suspicious': 0, 'harmless': 12, 'source': 'demo_virustotal'},
    '192.0.2.44': {'malicious': 5, 'suspicious': 1, 'harmless': 9, 'source': 'demo_virustotal'},
}


def ensure_dirs() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)



def load_suricata_logs(path: Path) -> pd.DataFrame:
    records: List[Dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pd.DataFrame(records)



def analyze_suricata(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=['src_ip', 'dns_queries', 'alert_count', 'suspicion_score'])

    dns_df = df[df.get('event_type').eq('dns')].copy() if 'event_type' in df.columns else pd.DataFrame()
    alert_df = df[df.get('event_type').eq('alert')].copy() if 'event_type' in df.columns else pd.DataFrame()

    dns_counts = dns_df.groupby('src_ip').size().rename('dns_queries') if not dns_df.empty else pd.Series(dtype=int)
    alert_counts = alert_df.groupby('src_ip').size().rename('alert_count') if not alert_df.empty else pd.Series(dtype=int)

    result = pd.concat([dns_counts, alert_counts], axis=1).fillna(0).reset_index()
    if result.empty:
        return pd.DataFrame(columns=['src_ip', 'dns_queries', 'alert_count', 'suspicion_score'])

    result['dns_queries'] = result['dns_queries'].astype(int)
    result['alert_count'] = result['alert_count'].astype(int)
    result['suspicion_score'] = result['dns_queries'] + result['alert_count'] * 3
    result = result.sort_values(['suspicion_score', 'alert_count', 'dns_queries'], ascending=False)
    return result



def fetch_virustotal_ip(ip: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return DEMO_VT.get(ip, {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'source': 'demo_virustotal'})

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()['data']['attributes']['last_analysis_stats']
        return {
            'malicious': data.get('malicious', 0),
            'suspicious': data.get('suspicious', 0),
            'harmless': data.get('harmless', 0),
            'source': 'virustotal_api'
        }
    except Exception as e:
        print(f'[WARN] VirusTotal request failed for {ip}: {e}. Using demo data.')
        return DEMO_VT.get(ip, {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'source': 'demo_virustotal'})



def fetch_vulners_data() -> List[Dict[str, Any]]:
    if not VULNERS_API_KEY:
        return DEMO_VULNERS

    url = 'https://vulners.com/api/v3/search/lucene/'
    headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': VULNERS_API_KEY,
    }
    payload = {
        'query': 'Fortinet AND RCE order:published',
        'skip': 0,
        'size': 10,
        'fields': ['id', 'title', 'published', 'cvss']
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        documents = response.json().get('data', {}).get('search', [])
        result = []
        for doc in documents:
            result.append({
                'id': doc.get('id', 'unknown'),
                'title': doc.get('title', 'No title'),
                'cvss': float(doc.get('cvss', 0) or 0),
                'published': doc.get('published', ''),
                'source': 'vulners_api'
            })
        return result or DEMO_VULNERS
    except Exception as e:
        print(f'[WARN] Vulners request failed: {e}. Using demo data.')
        return DEMO_VULNERS



def detect_threats(suricata_result: pd.DataFrame, vt_results: Dict[str, Dict[str, Any]], vulners_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious_ips = []
    for _, row in suricata_result.iterrows():
        ip = row['src_ip']
        vt_info = vt_results.get(ip, {})
        malicious = vt_info.get('malicious', 0)
        score = int(row['suspicion_score'])
        if score >= 4 or malicious >= 3:
            suspicious_ips.append({
                'src_ip': ip,
                'dns_queries': int(row['dns_queries']),
                'alert_count': int(row['alert_count']),
                'suspicion_score': score,
                'vt_malicious': malicious,
                'vt_suspicious': vt_info.get('suspicious', 0),
                'data_source': vt_info.get('source', 'unknown')
            })

    critical_vulns = [item for item in vulners_data if float(item.get('cvss', 0) or 0) >= 8.0]

    return {
        'suspicious_ips': suspicious_ips,
        'critical_vulnerabilities': critical_vulns,
        'summary': {
            'total_suspicious_ips': len(suspicious_ips),
            'total_critical_vulnerabilities': len(critical_vulns),
            'suricata_records_analyzed': int(suricata_result[['dns_queries', 'alert_count']].sum().sum()) if not suricata_result.empty else 0
        }
    }



def react_to_threats(report: Dict[str, Any]) -> None:
    print('\n=== Реагирование на угрозы ===')
    if not report['suspicious_ips'] and not report['critical_vulnerabilities']:
        print('Угрозы не обнаружены.')
        return

    for ip_info in report['suspicious_ips']:
        print(
            f"[ALERT] Подозрительный IP {ip_info['src_ip']} | "
            f"score={ip_info['suspicion_score']} | "
            f"VT malicious={ip_info['vt_malicious']} -> имитация блокировки IP"
        )

    for vuln in report['critical_vulnerabilities'][:5]:
        print(
            f"[ALERT] Найдена критическая уязвимость {vuln['id']} "
            f"(CVSS {vuln['cvss']}) -> уведомление администратору"
        )



def save_report(report: Dict[str, Any]) -> None:
    suspicious_df = pd.DataFrame(report['suspicious_ips'])
    critical_df = pd.DataFrame(report['critical_vulnerabilities'])

    combined_frames = []
    if not suspicious_df.empty:
        suspicious_df = suspicious_df.copy()
        suspicious_df['record_type'] = 'suspicious_ip'
        combined_frames.append(suspicious_df)
    if not critical_df.empty:
        critical_df = critical_df.copy()
        critical_df['record_type'] = 'critical_vulnerability'
        combined_frames.append(critical_df)

    if combined_frames:
        final_df = pd.concat(combined_frames, ignore_index=True)
    else:
        final_df = pd.DataFrame([{'record_type': 'no_threats'}])

    final_df.to_csv(REPORT_CSV, index=False, encoding='utf-8-sig')
    with REPORT_JSON.open('w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)



def save_chart(suricata_result: pd.DataFrame) -> None:
    if suricata_result.empty:
        plt.figure(figsize=(8, 4))
        plt.text(0.5, 0.5, 'Нет данных для построения графика', ha='center', va='center')
        plt.axis('off')
        plt.savefig(CHART_PNG, dpi=150, bbox_inches='tight')
        plt.close()
        return

    top_df = suricata_result.head(5)
    plt.figure(figsize=(10, 6))
    plt.bar(top_df['src_ip'], top_df['suspicion_score'])
    plt.title('Топ-5 подозрительных IP по уровню подозрительности')
    plt.xlabel('IP-адрес')
    plt.ylabel('Suspicion score')
    plt.xticks(rotation=25)
    plt.tight_layout()
    plt.savefig(CHART_PNG, dpi=150)
    plt.close()



def main() -> None:
    ensure_dirs()
    print('Загрузка логов Suricata...')
    suricata_df = load_suricata_logs(LOG_FILE)
    suricata_result = analyze_suricata(suricata_df)
    print(f'Обработано записей логов: {len(suricata_df)}')

    vt_results = {}
    for ip in suricata_result['src_ip'].head(5).tolist():
        vt_results[ip] = fetch_virustotal_ip(ip)

    vulners_data = fetch_vulners_data()
    report = detect_threats(suricata_result, vt_results, vulners_data)

    react_to_threats(report)
    save_report(report)
    save_chart(suricata_result)

    print('\n=== Итог ===')
    print(json.dumps(report['summary'], ensure_ascii=False, indent=2))
    print(f'CSV отчёт сохранен: {REPORT_CSV}')
    print(f'JSON отчёт сохранен: {REPORT_JSON}')
    print(f'График сохранен: {CHART_PNG}')


if __name__ == '__main__':
    main()
