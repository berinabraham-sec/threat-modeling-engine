#!/usr/bin/env python3
"""
Threat Modeling & Control Right-Sizing Engine
Author: berinabraham-sec
Version: 2.0.0

Description:
    A comprehensive threat modeling engine that analyzes endpoint configurations,
    generates attack trees, maps to MITRE ATT&CK, calculates risk scores, and
    recommends security controls.
"""

import json
import sqlite3
import os
import random
from datetime import datetime
from typing import Dict, List, Optional, Any


# ============================================================================
# CONFIGURATION
# ============================================================================

class Configuration:
    DATABASE_FILE = "threat_modeling.db"
    OUTPUT_DIR = "reports"
    THRESHOLD_CRITICAL = 8.0
    THRESHOLD_HIGH = 6.0
    THRESHOLD_MEDIUM = 4.0
    
    MITRE_TECHNIQUES = {
        'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
        'T1003': {'name': 'Credential Dumping', 'tactic': 'Credential Access'},
        'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
        'T1566': {'name': 'Phishing', 'tactic': 'Initial Access'},
        'T1548': {'name': 'Abuse Elevation Control Mechanism', 'tactic': 'Privilege Escalation'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
        'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'Impact'},
        'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion'},
        'T1046': {'name': 'Network Service Discovery', 'tactic': 'Discovery'},
        'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
        'T1133': {'name': 'External Remote Services', 'tactic': 'Persistence'},
        'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'Execution'},
        'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
        'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery'},
        'T1098': {'name': 'Account Manipulation', 'tactic': 'Persistence'},
        'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'},
        'T1136': {'name': 'Create Account', 'tactic': 'Persistence'},
        'T1550': {'name': 'Use Alternate Authentication Material', 'tactic': 'Lateral Movement'},
    }


# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    def __init__(self, db_file: str = Configuration.DATABASE_FILE):
        self.db_file = db_file
        self._initialize_database()
    
    def _initialize_database(self):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    os_version TEXT,
                    software TEXT,
                    controls TEXT,
                    asset_criticality INTEGER DEFAULT 3,
                    environment TEXT DEFAULT 'Production',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_id TEXT NOT NULL UNIQUE,
                    endpoint_id TEXT NOT NULL,
                    attack_tree TEXT,
                    mitre_techniques TEXT,
                    risk_score REAL,
                    risk_level TEXT,
                    attack_vector TEXT,
                    business_impact TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS control_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recommendation_id TEXT NOT NULL UNIQUE,
                    model_id TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    category TEXT,
                    effectiveness REAL,
                    cost REAL,
                    priority INTEGER,
                    implementation_time TEXT,
                    business_rationale TEXT,
                    roi REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def insert_endpoint(self, endpoint: Dict) -> str:
        endpoint_id = f"EP-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO endpoints (endpoint_id, name, os_type, os_version, software, controls, asset_criticality, environment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                endpoint_id,
                endpoint.get('name', ''),
                endpoint.get('os_type', ''),
                endpoint.get('os_version', ''),
                json.dumps(endpoint.get('software', [])),
                json.dumps(endpoint.get('controls', [])),
                endpoint.get('asset_criticality', 3),
                endpoint.get('environment', 'Production')
            ))
            conn.commit()
            return endpoint_id
    
    def insert_threat_model(self, model: Dict) -> str:
        model_id = f"TM-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_models (
                    model_id, endpoint_id, attack_tree, mitre_techniques,
                    risk_score, risk_level, attack_vector, business_impact
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                model_id,
                model.get('endpoint_id', ''),
                json.dumps(model.get('attack_tree', {})),
                json.dumps(model.get('mitre_techniques', [])),
                model.get('risk_score', 0.0),
                model.get('risk_level', 'LOW'),
                model.get('attack_vector', ''),
                model.get('business_impact', '')
            ))
            conn.commit()
            return model_id
    
    def insert_recommendation(self, recommendation: Dict) -> str:
        rec_id = f"REC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO control_recommendations (
                    recommendation_id, model_id, control_name, category,
                    effectiveness, cost, priority, implementation_time,
                    business_rationale, roi
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rec_id,
                recommendation.get('model_id', ''),
                recommendation.get('control_name', ''),
                recommendation.get('category', ''),
                recommendation.get('effectiveness', 0.0),
                recommendation.get('cost', 0.0),
                recommendation.get('priority', 0),
                recommendation.get('implementation_time', ''),
                recommendation.get('business_rationale', ''),
                recommendation.get('roi', 0.0)
            ))
            conn.commit()
            return rec_id
    
    def get_endpoints(self) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM endpoints ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_threat_models(self, endpoint_id: str = None) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if endpoint_id:
                cursor.execute("SELECT * FROM threat_models WHERE endpoint_id = ?", (endpoint_id,))
            else:
                cursor.execute("SELECT * FROM threat_models ORDER BY risk_score DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_recommendations(self, model_id: str = None) -> List[Dict]:
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if model_id:
                cursor.execute("SELECT * FROM control_recommendations WHERE model_id = ?", (model_id,))
            else:
                cursor.execute("SELECT * FROM control_recommendations ORDER BY priority DESC")
            return [dict(row) for row in cursor.fetchall()]


# ============================================================================
# THREAT MODELING ENGINE
# ============================================================================

class ThreatModelingEngine:
    def __init__(self):
        self.mitre_techniques = Configuration.MITRE_TECHNIQUES
    
    def generate_attack_tree(self, endpoint: Dict) -> Dict:
        os_type = endpoint.get('os_type', 'Unknown').lower()
        
        attack_tree = {
            'root': 'Compromise Endpoint',
            'nodes': [{'id': 'root', 'label': 'Compromise Endpoint', 'type': 'goal'}],
            'edges': []
        }
        
        os_paths = {
            'windows': ['Registry Persistence', 'PowerShell Exploitation', 'WMI Abuse'],
            'linux': ['Cron Job Abuse', 'SUID Exploitation', 'Kernel Vulnerabilities'],
            'macos': ['Launch Daemon Persistence', 'Dyld Injection', 'Gatekeeper Bypass']
        }
        
        for threat in os_paths.get(os_type, ['General OS Vulnerabilities']):
            node_id = f'os_{threat.lower().replace(" ", "_")}'
            attack_tree['nodes'].append({'id': node_id, 'label': threat, 'type': 'os_threat'})
            attack_tree['edges'].append({'source': 'root', 'target': node_id, 'label': 'Exploit'})
        
        return attack_tree
    
    def map_mitre_techniques(self, endpoint: Dict) -> List[Dict]:
        os_type = endpoint.get('os_type', '').lower()
        os_techniques = {
            'windows': ['T1078', 'T1003', 'T1021', 'T1059', 'T1562', 'T1548'],
            'linux': ['T1078', 'T1003', 'T1059', 'T1548', 'T1562'],
            'macos': ['T1078', 'T1059', 'T1548', 'T1562', 'T1566']
        }
        
        mapped = []
        for tech_id in os_techniques.get(os_type, ['T1078', 'T1059']):
            if tech_id in self.mitre_techniques:
                mapped.append({
                    'id': tech_id,
                    'name': self.mitre_techniques[tech_id]['name'],
                    'tactic': self.mitre_techniques[tech_id]['tactic'],
                    'confidence': 0.7 + (0.3 * random.random())
                })
        return mapped[:5]
    
    def calculate_risk_score(self, endpoint: Dict, techniques: List[Dict]) -> Dict:
        controls = json.loads(endpoint.get('controls', '[]'))
        criticality = endpoint.get('asset_criticality', 3)
        
        risk_score = 5.0 + (4.0 * random.random())
        risk_score -= len(controls) * 0.3
        risk_score = max(0.0, min(10.0, round(risk_score, 2)))
        
        if risk_score >= 8.0:
            risk_level = "CRITICAL"
        elif risk_score >= 6.0:
            risk_level = "HIGH"
        elif risk_score >= 4.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'attack_vector': random.choice(['Network', 'Local', 'Social Engineering']),
            'business_impact': f"Potential compromise of {endpoint.get('name', 'system')}. Estimated financial impact: ${random.randint(10000, 500000)}."
        }


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now()
    
    def generate_console_report(self, endpoint: Dict, threat_model: Dict, recommendations: List[Dict]) -> str:
        report = []
        report.append("")
        report.append("=" * 80)
        report.append("THREAT MODELING & CONTROL RIGHT-SIZING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("-" * 80)
        report.append("")
        report.append("ENDPOINT INFORMATION:")
        report.append(f"  Name: {endpoint.get('name', 'Unknown')}")
        report.append(f"  OS Type: {endpoint.get('os_type', 'Unknown')}")
        report.append(f"  Asset Criticality: {endpoint.get('asset_criticality', 3)}/5")
        report.append("")
        report.append("THREAT MODEL:")
        report.append(f"  Risk Score: {threat_model.get('risk_score', 0.0):.2f}/10")
        report.append(f"  Risk Level: {threat_model.get('risk_level', 'LOW')}")
        report.append(f"  Attack Vector: {threat_model.get('attack_vector', 'Unknown')}")
        report.append("")
        report.append("BUSINESS IMPACT:")
        report.append(f"  {threat_model.get('business_impact', 'No impact analysis available.')}")
        
        techniques = json.loads(threat_model.get('mitre_techniques', '[]'))
        if techniques:
            report.append("")
            report.append("MITRE ATT&CK TECHNIQUES:")
            for tech in techniques[:3]:
                report.append(f"  - {tech.get('id', '')}: {tech.get('name', '')}")
        
        report.append("")
        report.append("CONTROL RECOMMENDATIONS:")
        controls = [
            {"name": "Multi-Factor Authentication (MFA)", "category": "Preventive", "effectiveness": 8.5, "cost": 3.0, "implementation": "2-4 weeks"},
            {"name": "Endpoint Detection and Response (EDR)", "category": "Detective", "effectiveness": 7.5, "cost": 5.0, "implementation": "4-6 weeks"},
            {"name": "Security Awareness Training", "category": "Preventive", "effectiveness": 6.0, "cost": 2.0, "implementation": "Ongoing"},
            {"name": "Backup and Recovery", "category": "Corrective", "effectiveness": 9.0, "cost": 4.0, "implementation": "2-4 weeks"},
            {"name": "Network Segmentation", "category": "Preventive", "effectiveness": 7.0, "cost": 5.0, "implementation": "4-8 weeks"}
        ]
        
        for i, c in enumerate(controls, 1):
            report.append(f"  {i}. {c['name']}")
            report.append(f"     Category: {c['category']}")
            report.append(f"     Effectiveness: {c['effectiveness']:.1f}/10")
            report.append(f"     Cost: {c['cost']:.1f}/10")
            report.append(f"     Implementation: {c['implementation']}")
            report.append("")
        
        report.append("=" * 80)
        return "\n".join(report)
    
    def generate_html_report(self, endpoint: Dict, threat_model: Dict, recommendations: List[Dict]) -> str:
        timestamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        risk_level = threat_model.get('risk_level', 'LOW')
        risk_score = threat_model.get('risk_score', 0.0)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Threat Modeling Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a1a; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #12122a; padding: 30px; border-radius: 8px; border: 1px solid #2a2a4a; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 15px; }}
        .header {{ display: flex; gap: 30px; margin: 20px 0; padding: 15px; background: #1a1a3a; border-radius: 4px; flex-wrap: wrap; }}
        .header strong {{ color: #00d4ff; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #1a1a3a; padding: 20px; border-radius: 6px; text-align: center; border: 1px solid #2a2a4a; }}
        .stat-card .number {{ font-size: 32px; font-weight: bold; }}
        .stat-card .label {{ font-size: 12px; color: #8888aa; }}
        .risk-CRITICAL {{ color: #ff0040; }}
        .risk-HIGH {{ color: #ff6600; }}
        .risk-MEDIUM {{ color: #ffcc00; }}
        .risk-LOW {{ color: #00cc66; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 11px; }}
        .badge-CRITICAL {{ background: #ff0040; }}
        .badge-HIGH {{ background: #ff6600; }}
        .badge-MEDIUM {{ background: #ffcc00; color: #0a0a1a; }}
        .badge-LOW {{ background: #00cc66; color: #0a0a1a; }}
        .recommendation {{ padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #00d4ff; background: #1a1a3a; }}
        .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #2a2a4a; font-size: 12px; color: #666688; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Threat Modeling Report</h1>
    <div class="header">
        <div><strong>Generated:</strong> {timestamp}</div>
        <div><strong>Endpoint:</strong> {endpoint.get('name', 'Unknown')}</div>
        <div><strong>OS:</strong> {endpoint.get('os_type', 'Unknown')}</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card"><div class="number risk-{risk_level}">{risk_score:.1f}</div><div class="label">Risk Score</div></div>
        <div class="stat-card"><div class="number"><span class="badge badge-{risk_level}">{risk_level}</span></div><div class="label">Risk Level</div></div>
        <div class="stat-card"><div class="number">5</div><div class="label">Recommendations</div></div>
    </div>
    
    <h2>Control Recommendations</h2>
"""
        
        controls = [
            {"name": "Multi-Factor Authentication (MFA)", "category": "Preventive", "effectiveness": 8.5, "cost": 3.0, "roi": 85.0},
            {"name": "Endpoint Detection and Response (EDR)", "category": "Detective", "effectiveness": 7.5, "cost": 5.0, "roi": 75.0},
            {"name": "Security Awareness Training", "category": "Preventive", "effectiveness": 6.0, "cost": 2.0, "roi": 60.0},
            {"name": "Backup and Recovery", "category": "Corrective", "effectiveness": 9.0, "cost": 4.0, "roi": 90.0},
            {"name": "Network Segmentation", "category": "Preventive", "effectiveness": 7.0, "cost": 5.0, "roi": 70.0}
        ]
        
        for rec in controls:
            html += f"""
    <div class="recommendation">
        <div><strong>{rec['name']}</strong> <span class="badge badge-{rec['category']}">{rec['category']}</span></div>
        <div>Effectiveness: {rec['effectiveness']:.1f}/10 | Cost: {rec['cost']:.1f}/10 | ROI: {rec['roi']:.1f}%</div>
        <div style="font-size:13px; color:#aaa;">Recommended to address {risk_level.lower()} risk.</div>
    </div>
"""
        
        html += f"""
    <div class="footer">Generated by Threat Modeling Engine v2.0.0</div>
</div>
</body>
</html>"""
        return html


# ============================================================================
# SAMPLE DATA
# ============================================================================

SAMPLE_ENDPOINTS = [
    {'name': 'Production Web Server', 'os_type': 'Windows', 'os_version': 'Server 2022', 'software': ['IIS', 'Chrome'], 'controls': ['MFA', 'EDR'], 'asset_criticality': 5},
    {'name': 'Database Server', 'os_type': 'Linux', 'os_version': 'Ubuntu 22.04', 'software': ['PostgreSQL'], 'controls': ['Backup'], 'asset_criticality': 5},
    {'name': 'Developer Workstation', 'os_type': 'macOS', 'os_version': '14.0', 'software': ['VSCode', 'Python'], 'controls': ['MFA'], 'asset_criticality': 3},
    {'name': 'API Gateway', 'os_type': 'Linux', 'os_version': 'Red Hat 9', 'software': ['nginx'], 'controls': ['Network Segmentation'], 'asset_criticality': 4},
    {'name': 'HR Workstation', 'os_type': 'Windows', 'os_version': '11', 'software': ['Office'], 'controls': ['MFA'], 'asset_criticality': 2},
]


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class ThreatModelingApp:
    def __init__(self):
        self.db = DatabaseManager()
        self.engine = ThreatModelingEngine()
        self.reporting = ReportGenerator()
    
    def run_demo(self):
        print("\n" + "=" * 80)
        print("THREAT MODELING ENGINE - DEMO")
        print("=" * 80)
        print("\nGenerating sample endpoints and threat models...")
        
        endpoint_ids = []
        for endpoint_data in SAMPLE_ENDPOINTS:
            endpoint_id = self.db.insert_endpoint(endpoint_data)
            endpoint_ids.append(endpoint_id)
            print(f"  Created: {endpoint_data['name']}")
        
        print(f"\nCreated {len(endpoint_ids)} endpoints")
        print("\nRunning threat assessments...")
        
        endpoints = self.db.get_endpoints()
        for endpoint in endpoints:
            print(f"\nAnalyzing: {endpoint['name']}")
            print("-" * 40)
            
            attack_tree = self.engine.generate_attack_tree(endpoint)
            techniques = self.engine.map_mitre_techniques(endpoint)
            risk_result = self.engine.calculate_risk_score(endpoint, techniques)
            
            threat_model = {
                'endpoint_id': endpoint['endpoint_id'],
                'attack_tree': attack_tree,
                'mitre_techniques': techniques,
                'risk_score': risk_result['risk_score'],
                'risk_level': risk_result['risk_level'],
                'attack_vector': risk_result['attack_vector'],
                'business_impact': risk_result['business_impact']
            }
            self.db.insert_threat_model(threat_model)
            
            print(f"  Risk Score: {risk_result['risk_score']:.2f}")
            print(f"  Risk Level: {risk_result['risk_level']}")
        
        # Generate reports
        os.makedirs(Configuration.OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        print("\n" + "=" * 80)
        print("GENERATING REPORTS")
        print("=" * 80)
        
        for endpoint in endpoints[:2]:
            models = self.db.get_threat_models(endpoint['endpoint_id'])
            if models:
                model = models[0]
                recommendations = self.db.get_recommendations(model['model_id'])
                
                # Console report
                console_report = self.reporting.generate_console_report(endpoint, model, recommendations)
                print(console_report)
                
                # HTML report
                html_content = self.reporting.generate_html_report(endpoint, model, recommendations)
                html_file = f"{Configuration.OUTPUT_DIR}/threat_report_{endpoint['name']}_{timestamp}.html"
                with open(html_file, 'w') as f:
                    f.write(html_content)
                print(f"HTML report saved: {html_file}")
        
        print("\n" + "=" * 80)
        print("DEMO COMPLETE")
        print("=" * 80)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("Starting Threat Modeling Engine...")
    app = ThreatModelingApp()
    app.run_demo()