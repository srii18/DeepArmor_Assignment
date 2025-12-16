import boto3
import json
import os
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration - Loaded from .env file
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')  # Default to us-east-1 if not specified

# SAFETY: Only scan resources with this prefix
TEST_RESOURCE_PREFIX = 'deeparmor-test'

class AWSSecurityScanner:
    def __init__(self, access_key, secret_key, region):
        """Initialize AWS clients"""
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        self.s3_client = self.session.client('s3')
        self.rds_client = self.session.client('rds')
        self.ec2_client = self.session.client('ec2')
        
        self.findings = []
        self.scanned_resources = {'s3': [], 'rds': [], 'sg': []}
    
    def scan_s3_buckets(self):
        """Check S3 buckets for security misconfigurations"""
        print("\n[*] Scanning S3 Buckets...")
        print("="*60)
        
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            
            test_buckets = [b for b in buckets if TEST_RESOURCE_PREFIX in b['Name']]
            
            if not test_buckets:
                print(f"⚠️  No buckets found with prefix '{TEST_RESOURCE_PREFIX}'")
                print("   Make sure you named your test bucket correctly!")
                return
            
            print(f"Found {len(test_buckets)} test bucket(s) to scan")
            print(f"(Skipping {len(buckets) - len(test_buckets)} existing buckets)")
            
            for bucket in test_buckets:
                bucket_name = bucket['Name']
                self.scanned_resources['s3'].append(bucket_name)
                print(f"\n✓ Checking bucket: {bucket_name}")
                
                # Check 1: Public Access
                try:
                    public_access_block = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    
                    config = public_access_block['PublicAccessBlockConfiguration']
                    if not all([config['BlockPublicAcls'], config['BlockPublicPolicy'], 
                               config['IgnorePublicAcls'], config['RestrictPublicBuckets']]):
                        self.findings.append({
                            'Resource': bucket_name,
                            'Type': 'S3 Bucket',
                            'Issue': 'Publicly Accessible',
                            'Severity': 'HIGH',
                            'Description': 'Bucket does not have all public access blocks enabled'
                        })
                        print(f"  🔴 ISSUE: Bucket is publicly accessible")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self.findings.append({
                            'Resource': bucket_name,
                            'Type': 'S3 Bucket',
                            'Issue': 'Publicly Accessible',
                            'Severity': 'HIGH',
                            'Description': 'No public access block configuration found (bucket is public)'
                        })
                        print(f"  🔴 ISSUE: No public access block configured (PUBLIC)")
                
                # Check 2: Logging
                try:
                    logging = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                    if 'LoggingEnabled' not in logging:
                        self.findings.append({
                            'Resource': bucket_name,
                            'Type': 'S3 Bucket',
                            'Issue': 'Logging Disabled',
                            'Severity': 'MEDIUM',
                            'Description': 'Server access logging is not enabled'
                        })
                        print(f"  🟡 ISSUE: Logging is disabled")
                    else:
                        print(f"  ✓ Logging is enabled")
                except ClientError:
                    pass
                
                # Check 3: Versioning
                try:
                    versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self.findings.append({
                            'Resource': bucket_name,
                            'Type': 'S3 Bucket',
                            'Issue': 'Versioning Disabled',
                            'Severity': 'MEDIUM',
                            'Description': 'Bucket versioning is not enabled'
                        })
                        print(f"  🟡 ISSUE: Versioning is disabled")
                    else:
                        print(f"  ✓ Versioning is enabled")
                except ClientError:
                    pass
                    
        except ClientError as e:
            print(f"❌ Error scanning S3 buckets: {e}")
    
    def scan_rds_instances(self):
        """Check RDS instances for security misconfigurations"""
        print("\n[*] Scanning RDS Instances...")
        print("="*60)
        
        try:
            instances = self.rds_client.describe_db_instances()['DBInstances']
            
            test_instances = [i for i in instances if TEST_RESOURCE_PREFIX in i['DBInstanceIdentifier']]
            
            if not test_instances:
                print(f"⚠️  No RDS instances found with prefix '{TEST_RESOURCE_PREFIX}'")
                print("   Your RDS instance might still be creating (takes 5-10 minutes)")
                print(f"   (Found {len(instances)} existing RDS instance(s) - skipping them)")
                return
            
            print(f"Found {len(test_instances)} test RDS instance(s) to scan")
            print(f"(Skipping {len(instances) - len(test_instances)} existing instances)")
            
            for instance in test_instances:
                db_id = instance['DBInstanceIdentifier']
                self.scanned_resources['rds'].append(db_id)
                print(f"\n✓ Checking RDS instance: {db_id}")
                
                # Check 1: Public Accessibility
                if instance.get('PubliclyAccessible', False):
                    self.findings.append({
                        'Resource': db_id,
                        'Type': 'RDS Instance',
                        'Issue': 'Publicly Accessible',
                        'Severity': 'CRITICAL',
                        'Description': 'RDS instance is publicly accessible from the internet'
                    })
                    print(f"  🔴 ISSUE: Instance is publicly accessible")
                else:
                    print(f"  ✓ Instance is private")
                
                # Check 2: Delete Protection
                if not instance.get('DeletionProtection', False):
                    self.findings.append({
                        'Resource': db_id,
                        'Type': 'RDS Instance',
                        'Issue': 'No Delete Protection',
                        'Severity': 'MEDIUM',
                        'Description': 'Deletion protection is not enabled'
                    })
                    print(f"  🟡 ISSUE: Delete protection is disabled")
                else:
                    print(f"  ✓ Delete protection enabled")
                
                # Check 3: Backup Retention
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                if backup_retention == 0:
                    self.findings.append({
                        'Resource': db_id,
                        'Type': 'RDS Instance',
                        'Issue': 'Backups Disabled',
                        'Severity': 'HIGH',
                        'Description': 'Automated backups are not enabled'
                    })
                    print(f"  🔴 ISSUE: Automated backups are disabled")
                else:
                    print(f"  ✓ Backups enabled ({backup_retention} day retention)")
                    
        except ClientError as e:
            print(f"❌ Error scanning RDS instances: {e}")
    
    def scan_security_groups(self):
        """Check Security Groups for risky rules"""
        print("\n[*] Scanning Security Groups...")
        print("="*60)
        
        try:
            security_groups = self.ec2_client.describe_security_groups()['SecurityGroups']
            
            test_sgs = [sg for sg in security_groups if TEST_RESOURCE_PREFIX in sg['GroupName']]
            
            if not test_sgs:
                print(f"⚠️  No security groups found with prefix '{TEST_RESOURCE_PREFIX}'")
                print("   Make sure you named your test security group correctly!")
                print(f"   (Found {len(security_groups)} existing security groups - skipping them)")
                return
            
            print(f"Found {len(test_sgs)} test security group(s) to scan")
            print(f"(Skipping {len(security_groups) - len(test_sgs)} existing security groups)")
            
            for sg in test_sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                self.scanned_resources['sg'].append(f"{sg_name} ({sg_id})")
                
                print(f"\n✓ Checking Security Group: {sg_name} ({sg_id})")
                
                issues_found = False
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 'N/A')
                    to_port = rule.get('ToPort', 'N/A')
                    
                    # Check if rule allows access from anywhere (0.0.0.0/0)
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            # Check for SSH (port 22)
                            if from_port == 22 or to_port == 22:
                                self.findings.append({
                                    'Resource': f"{sg_name} ({sg_id})",
                                    'Type': 'Security Group',
                                    'Issue': 'Unrestricted SSH Access',
                                    'Severity': 'CRITICAL',
                                    'Description': 'SSH port (22) is open to the internet (0.0.0.0/0)'
                                })
                                print(f"  🔴 ISSUE: SSH (port 22) open to public (0.0.0.0/0)")
                                issues_found = True
                            
                            # Check for MongoDB (port 27017)
                            if from_port == 27017 or to_port == 27017:
                                self.findings.append({
                                    'Resource': f"{sg_name} ({sg_id})",
                                    'Type': 'Security Group',
                                    'Issue': 'Unrestricted MongoDB Access',
                                    'Severity': 'CRITICAL',
                                    'Description': 'MongoDB port (27017) is open to the internet (0.0.0.0/0)'
                                })
                                print(f"  🔴 ISSUE: MongoDB (port 27017) open to public (0.0.0.0/0)")
                                issues_found = True
                
                if not issues_found:
                    print(f"  ✓ No risky rules found")
                                
        except ClientError as e:
            print(f"❌ Error scanning security groups: {e}")
    
    def generate_report(self):
        """Generate a summary report of all findings"""
        print("\n" + "="*60)
        print("SECURITY SCAN REPORT")
        print("="*60)
        
        # Show what was scanned
        print("\n📋 Resources Scanned:")
        print(f"  S3 Buckets: {len(self.scanned_resources['s3'])}")
        for bucket in self.scanned_resources['s3']:
            print(f"    - {bucket}")
        
        print(f"  RDS Instances: {len(self.scanned_resources['rds'])}")
        for rds in self.scanned_resources['rds']:
            print(f"    - {rds}")
        
        print(f"  Security Groups: {len(self.scanned_resources['sg'])}")
        for sg in self.scanned_resources['sg']:
            print(f"    - {sg}")
        
        if not self.findings:
            print("\n✅ No security misconfigurations found!")
            print("   (This is unexpected - your test resources should have issues)")
            return
        
        # Count by severity
        critical = sum(1 for f in self.findings if f['Severity'] == 'CRITICAL')
        high = sum(1 for f in self.findings if f['Severity'] == 'HIGH')
        medium = sum(1 for f in self.findings if f['Severity'] == 'MEDIUM')
        
        print(f"\n🔍 Total Issues Found: {len(self.findings)}")
        print(f"  🔴 CRITICAL: {critical}")
        print(f"  🔴 HIGH: {high}")
        print(f"  🟡 MEDIUM: {medium}")
        
        print("\n" + "-"*60)
        print("DETAILED FINDINGS:")
        print("-"*60)
        
        for i, finding in enumerate(self.findings, 1):
            severity_icon = "🔴" if finding['Severity'] in ['CRITICAL', 'HIGH'] else "🟡"
            print(f"\n{i}. {severity_icon} [{finding['Severity']}] {finding['Issue']}")
            print(f"   Resource: {finding['Resource']}")
            print(f"   Type: {finding['Type']}")
            print(f"   Description: {finding['Description']}")
        
        # Save to JSON file
        report = {
            'scan_summary': {
                'total_findings': len(self.findings),
                'critical': critical,
                'high': high,
                'medium': medium,
                'resources_scanned': self.scanned_resources
            },
            'findings': self.findings
        }
        
        with open('security_findings.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Detailed report saved to: security_findings.json")
        
        # Cleanup reminder
        print("\n" + "="*60)
        print("⚠️  CLEANUP REMINDER")
        print("="*60)
        print("Don't forget to DELETE these test resources when done:")
        for bucket in self.scanned_resources['s3']:
            print(f"  • S3 Bucket: {bucket}")
        for rds in self.scanned_resources['rds']:
            print(f"  • RDS Instance: {rds}")
        for sg in self.scanned_resources['sg']:
            print(f"  • Security Group: {sg}")

def main():
    print("="*60)
    print("AWS SECURITY MISCONFIGURATION SCANNER")
    print("(Safe Mode - Only scans test resources)")
    print("="*60)
    print(f"\n🔒 Safety: Only scanning resources with prefix '{TEST_RESOURCE_PREFIX}'")
    print(f"   All other existing resources will be IGNORED")
    
    # Initialize scanner
    scanner = AWSSecurityScanner(
        access_key=AWS_ACCESS_KEY_ID,
        secret_key=AWS_SECRET_ACCESS_KEY,
        region=AWS_REGION
    )
    
    # Run all scans
    scanner.scan_s3_buckets()
    scanner.scan_rds_instances()
    scanner.scan_security_groups()
    
    # Generate report
    scanner.generate_report()
    
    print("\n" + "="*60)
    print("✅ Scan Complete!")
    print("="*60)

if __name__ == "__main__":
    main()