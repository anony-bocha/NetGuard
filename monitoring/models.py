import uuid
from django.db import models
from django.utils import timezone

# Severity choices for alerts
SEVERITY_CHOICES = [
    ('Critical', 'Critical'),
    ('High', 'High'),
    ('Medium', 'Medium'),
    ('Low', 'Low'),
    ('Info', 'Info'),
]

# Confidence choices for alerts
CONFIDENCE_CHOICES = [
    ('High', 'High'),
    ('Medium', 'Medium'),
    ('Low', 'Low'),
]

# Status of assets
ASSET_STATUS = [
    ('Online', 'Online'),
    ('Offline', 'Offline'),
    ('Unknown', 'Unknown'),
]

# --- Asset Model ---
class Asset(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    asset_type = models.CharField(max_length=100, blank=True, null=True)  # Server, Workstation, IoT
    status = models.CharField(max_length=20, choices=ASSET_STATUS, default='Unknown')
    last_seen = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.hostname or self.ip_address}"

# --- Attack Type Model ---
class AttackType(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='Medium')

    def __str__(self):
        return self.name

# --- Scan Model ---
class Scan(models.Model):
    SCAN_TYPES = [
        ('Ping', 'Ping'),
        ('Nmap', 'Nmap'),
        ('Vuln', 'Vulnerability'),
        ('Custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPES)
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(blank=True, null=True)
    result_summary = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.scan_type} scan on {self.asset}"

# --- Alert Model ---
class Alert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='alerts')
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)  # ADD THIS
    attack_type = models.ForeignKey(AttackType, on_delete=models.SET_NULL, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='Medium')
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default='Medium')
    description = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)


    def __str__(self):
        return f"{self.attack_type} on {self.asset} ({self.severity})"
